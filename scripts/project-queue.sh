#!/bin/bash
# project-queue.sh — GitHub Projects V2 queue operations for CFGMS pipeline
# Reads field IDs from .claude/pipeline.yaml; uses gh api graphql exclusively.
# No gh issue calls; no label manipulation.
# Exit codes: 0=success, 1=GraphQL API error, 2=invalid arguments
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_YAML="${SCRIPT_DIR}/../.claude/pipeline.yaml"
REPO_OWNER="cfg-is"
REPO_NAME="cfgms"

# ── Utilities ─────────────────────────────────────────────────────────────────

_usage() {
    cat >&2 <<'EOF'
Usage: project-queue.sh <subcommand> [args]

Subcommands:
  create-draft <story_num> <title> <body_file>   Create a draft project item (Status=Draft)
  list-by-status <status>                         List items by status (JSON array)
  get-item <item_id>                              Get full item JSON
  update-field <item_id> <field> <value>          Update a field value
  add-issue <issue_num>                            Add a GitHub issue to the project
  add-pr <pr_num>                                 Add a GitHub PR to the project
  set-pr <item_id> <pr_num>                       Record PR number against a project item
  delete-item <item_id>                           Remove an item from the project
EOF
    exit 2
}

_require_yaml() {
    [[ -f "$PIPELINE_YAML" ]] || {
        printf 'Error: pipeline.yaml not found: %s\n' "$PIPELINE_YAML" >&2
        exit 1
    }
}

_yaml_get() {
    local key="$1"
    if command -v yq >/dev/null 2>&1; then
        yq e ".${key}" "$PIPELINE_YAML"
    else
        # Pure stdlib fallback: parse simple key: value YAML without PyYAML
        YAML_FILE="$PIPELINE_YAML" YAML_KEY="$key" python3 -c '
import re, os, sys
key = os.environ["YAML_KEY"]
pattern = re.compile(r"^" + re.escape(key) + r":\s*(.*)")
with open(os.environ["YAML_FILE"]) as _f:
    for _line in _f:
        _m = pattern.match(_line.rstrip())
        if _m:
            print(_m.group(1).strip())
            sys.exit(0)
sys.exit(1)
'
    fi
}

_status_option_id() {
    local name="$1"
    local key
    case "$name" in
        Draft)         key=status_option_Draft ;;
        Ready)         key=status_option_Ready ;;
        "In Progress") key=status_option_In_Progress ;;
        Reviewing)     key=status_option_Reviewing ;;
        Fix)           key=status_option_Fix ;;
        Failed)        key=status_option_Failed ;;
        Blocked)       key=status_option_Blocked ;;
        Done)          key=status_option_Done ;;
        *) printf 'Error: unknown status option: %s\n' "$name" >&2; exit 1 ;;
    esac
    _yaml_get "$key"
}

# ── Subcommands ───────────────────────────────────────────────────────────────

cmd_create_draft() {
    [[ $# -ge 3 ]] || {
        printf 'Usage: %s create-draft <story_num> <title> <body_file>\n' "$0" >&2
        exit 2
    }
    local story_num="$1" title="$2" body_file="$3"
    [[ -f "$body_file" ]] || {
        printf 'Error: body_file not found: %s\n' "$body_file" >&2
        exit 2
    }
    _require_yaml

    local project_id status_field_id draft_option_id
    project_id=$(_yaml_get project_id)
    status_field_id=$(_yaml_get status_field_id)
    draft_option_id=$(_status_option_id Draft)

    GQ_PROJECT_ID="$project_id" GQ_TITLE="$title" GQ_BODY_FILE="$body_file" \
    GQ_FIELD_ID="$status_field_id" GQ_OPTION_ID="$draft_option_id" \
    GQ_STORY_NUM="$story_num" python3 - <<'PYEOF'
import json, os, subprocess, sys


def graphql(payload):
    r = subprocess.run(
        ['gh', 'api', 'graphql', '--input', '-'],
        input=json.dumps(payload).encode(),
        capture_output=True
    )
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    resp = json.loads(r.stdout)
    if resp.get('errors'):
        for e in resp['errors']:
            print(e.get('message', str(e)), file=sys.stderr)
        sys.exit(1)
    return resp['data']


project_id = os.environ['GQ_PROJECT_ID']
title = os.environ['GQ_TITLE']
body_file = os.environ['GQ_BODY_FILE']
field_id = os.environ['GQ_FIELD_ID']
option_id = os.environ['GQ_OPTION_ID']
story_num = int(os.environ['GQ_STORY_NUM'])
body = open(body_file).read()

data = graphql({
    'query': (
        'mutation($p:ID!,$t:String!,$b:String!){'
        'addProjectV2DraftIssue(input:{projectId:$p,title:$t,body:$b}){'
        'projectItem{id}}}'
    ),
    'variables': {'p': project_id, 't': title, 'b': body}
})
item_id = data['addProjectV2DraftIssue']['projectItem']['id']

graphql({
    'query': (
        'mutation($p:ID!,$i:ID!,$f:ID!,$o:String!){'
        'updateProjectV2ItemFieldValue(input:{projectId:$p,itemId:$i,fieldId:$f,'
        'value:{singleSelectOptionId:$o}}){projectV2Item{id}}}'
    ),
    'variables': {'p': project_id, 'i': item_id, 'f': field_id, 'o': option_id}
})

print(json.dumps({
    'item_id': item_id,
    'story_num': story_num,
    'title': title,
    'status': 'Draft'
}))
PYEOF
}

cmd_list_by_status() {
    [[ $# -ge 1 ]] || {
        printf 'Usage: %s list-by-status <status>\n' "$0" >&2
        exit 2
    }
    local status="$1"
    _require_yaml

    local project_id
    project_id=$(_yaml_get project_id)

    GQ_PROJECT_ID="$project_id" GQ_STATUS="$status" python3 - <<'PYEOF'
import json, os, subprocess, sys


def graphql(payload):
    r = subprocess.run(
        ['gh', 'api', 'graphql', '--input', '-'],
        input=json.dumps(payload).encode(),
        capture_output=True
    )
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    resp = json.loads(r.stdout)
    if resp.get('errors'):
        for e in resp['errors']:
            print(e.get('message', str(e)), file=sys.stderr)
        sys.exit(1)
    return resp['data']


project_id = os.environ['GQ_PROJECT_ID']
status_filter = os.environ['GQ_STATUS']

query = (
    'query($p:ID!,$cursor:String){'
    'node(id:$p){'
    '...on ProjectV2{'
    'items(first:100,after:$cursor){'
    'pageInfo{hasNextPage endCursor}'
    'nodes{'
    'id '
    'content{'
    '...on DraftIssue{title}'
    '...on Issue{number title}'
    '...on PullRequest{number title}'
    '}'
    'fieldValues(first:20){'
    'nodes{'
    '...on ProjectV2ItemFieldSingleSelectValue{'
    'name '
    'field{...on ProjectV2SingleSelectField{name}}'
    '}'
    '}'
    '}'
    '}'
    '}'
    '}'
    '}'
    '}'
)

results = []
cursor = None
while True:
    variables = {'p': project_id}
    if cursor:
        variables['cursor'] = cursor
    data = graphql({'query': query, 'variables': variables})
    items_data = data['node']['items']
    for item in items_data['nodes']:
        status_val = None
        for fv in (item.get('fieldValues') or {}).get('nodes', []):
            if not fv:
                continue
            field = (fv.get('field') or {})
            if field.get('name', '').lower() == 'status':
                status_val = fv.get('name', '')
                break
        if status_val != status_filter:
            continue
        content = item.get('content') or {}
        results.append({
            'item_id': item['id'],
            'issue_num': content.get('number', None),
            'title': content.get('title', '')
        })
    page_info = items_data['pageInfo']
    if not page_info['hasNextPage']:
        break
    cursor = page_info['endCursor']

print(json.dumps(results))
PYEOF
}

cmd_get_item() {
    [[ $# -ge 1 ]] || {
        printf 'Usage: %s get-item <item_id>\n' "$0" >&2
        exit 2
    }
    local item_id="$1"

    GQ_ITEM_ID="$item_id" python3 - <<'PYEOF'
import json, os, subprocess, sys


def graphql(payload):
    r = subprocess.run(
        ['gh', 'api', 'graphql', '--input', '-'],
        input=json.dumps(payload).encode(),
        capture_output=True
    )
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    resp = json.loads(r.stdout)
    if resp.get('errors'):
        for e in resp['errors']:
            print(e.get('message', str(e)), file=sys.stderr)
        sys.exit(1)
    return resp['data']


item_id = os.environ['GQ_ITEM_ID']

query = (
    'query($id:ID!){'
    'node(id:$id){'
    '...on ProjectV2Item{'
    'id '
    'content{'
    '...on DraftIssue{title body}'
    '...on Issue{number title body}'
    '...on PullRequest{number title body}'
    '}'
    'fieldValues(first:20){'
    'nodes{'
    '...on ProjectV2ItemFieldSingleSelectValue{'
    'name '
    'field{...on ProjectV2SingleSelectField{name}}'
    '}'
    '...on ProjectV2ItemFieldTextValue{'
    'text '
    'field{...on ProjectV2Field{name}}'
    '}'
    '}'
    '}'
    '}'
    '}'
    '}'
)

data = graphql({'query': query, 'variables': {'id': item_id}})
node = data['node']
content = node.get('content') or {}

status = None
text_fields = {}
for fv in (node.get('fieldValues') or {}).get('nodes', []):
    if not fv:
        continue
    field = (fv.get('field') or {})
    field_name = field.get('name', '')
    if field_name.lower() == 'status':
        status = fv.get('name', '')
    elif 'text' in fv and field_name:
        text_fields[field_name] = fv.get('text', '')

print(json.dumps({
    'item_id': node['id'],
    'title': content.get('title', ''),
    'body': content.get('body', ''),
    'status': status,
    'issue_num': content.get('number', None),
    'fields': text_fields
}))
PYEOF
}

cmd_update_field() {
    [[ $# -ge 3 ]] || {
        printf 'Usage: %s update-field <item_id> <field> <value>\n' "$0" >&2
        exit 2
    }
    local item_id="$1" field_name="$2" field_value="$3"
    _require_yaml

    local project_id
    project_id=$(_yaml_get project_id)

    GQ_PROJECT_ID="$project_id" GQ_ITEM_ID="$item_id" \
    GQ_FIELD_NAME="$field_name" GQ_FIELD_VALUE="$field_value" \
    GQ_PIPELINE_YAML="$PIPELINE_YAML" python3 - <<'PYEOF'
import json, os, subprocess, sys


def graphql(payload):
    r = subprocess.run(
        ['gh', 'api', 'graphql', '--input', '-'],
        input=json.dumps(payload).encode(),
        capture_output=True
    )
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    resp = json.loads(r.stdout)
    if resp.get('errors'):
        for e in resp['errors']:
            print(e.get('message', str(e)), file=sys.stderr)
        sys.exit(1)
    return resp['data']


project_id = os.environ['GQ_PROJECT_ID']
item_id = os.environ['GQ_ITEM_ID']
field_name = os.environ['GQ_FIELD_NAME']
field_value = os.environ['GQ_FIELD_VALUE']
yaml_path = os.environ['GQ_PIPELINE_YAML']

# Parse simple key: value YAML using stdlib only (no PyYAML required)
import re as _re
cfg = {}
with open(yaml_path) as _f:
    for _line in _f:
        _m = _re.match(r'^([A-Za-z0-9_]+):\s*(.*)', _line.rstrip())
        if _m:
            cfg[_m.group(1)] = _m.group(2).strip()

status_field_id = cfg.get('status_field_id', '')
status_options = {
    'Draft': cfg.get('status_option_Draft', ''),
    'Ready': cfg.get('status_option_Ready', ''),
    'In Progress': cfg.get('status_option_In_Progress', ''),
    'Reviewing': cfg.get('status_option_Reviewing', ''),
    'Fix': cfg.get('status_option_Fix', ''),
    'Failed': cfg.get('status_option_Failed', ''),
    'Blocked': cfg.get('status_option_Blocked', ''),
    'Done': cfg.get('status_option_Done', ''),
}

if field_name.lower() == 'status':
    option_id = status_options.get(field_value, '')
    if not option_id:
        print(f'Error: unknown status value: {field_value}', file=sys.stderr)
        sys.exit(1)
    graphql({
        'query': (
            'mutation($p:ID!,$i:ID!,$f:ID!,$o:String!){'
            'updateProjectV2ItemFieldValue(input:{projectId:$p,itemId:$i,fieldId:$f,'
            'value:{singleSelectOptionId:$o}}){projectV2Item{id}}}'
        ),
        'variables': {'p': project_id, 'i': item_id, 'f': status_field_id, 'o': option_id}
    })
else:
    # Query project fields to find the field by name and determine its type
    fields_data = graphql({
        'query': (
            'query($p:ID!){'
            'node(id:$p){'
            '...on ProjectV2{'
            'fields(first:50){'
            'nodes{'
            '...on ProjectV2Field{id name dataType}'
            '...on ProjectV2SingleSelectField{id name dataType options{id name}}'
            '...on ProjectV2IterationField{id name dataType}'
            '}'
            '}'
            '}'
            '}'
            '}'
        ),
        'variables': {'p': project_id}
    })
    fields = (fields_data['node']['fields'] or {}).get('nodes', [])
    field_node = next(
        (f for f in fields if f and f.get('name', '').lower() == field_name.lower()),
        None
    )
    if not field_node:
        print(f'Error: field not found in project: {field_name}', file=sys.stderr)
        sys.exit(1)

    fid = field_node['id']
    data_type = field_node.get('dataType', 'TEXT')

    if data_type == 'SINGLE_SELECT':
        option = next(
            (o for o in field_node.get('options', []) if o['name'] == field_value),
            None
        )
        if not option:
            print(f'Error: unknown option {field_value!r} for field {field_name!r}', file=sys.stderr)
            sys.exit(1)
        graphql({
            'query': (
                'mutation($p:ID!,$i:ID!,$f:ID!,$o:String!){'
                'updateProjectV2ItemFieldValue(input:{projectId:$p,itemId:$i,fieldId:$f,'
                'value:{singleSelectOptionId:$o}}){projectV2Item{id}}}'
            ),
            'variables': {'p': project_id, 'i': item_id, 'f': fid, 'o': option['id']}
        })
    else:
        graphql({
            'query': (
                'mutation($p:ID!,$i:ID!,$f:ID!,$v:String!){'
                'updateProjectV2ItemFieldValue(input:{projectId:$p,itemId:$i,fieldId:$f,'
                'value:{text:$v}}){projectV2Item{id}}}'
            ),
            'variables': {'p': project_id, 'i': item_id, 'f': fid, 'v': field_value}
        })

print(json.dumps({
    'updated': True,
    'item_id': item_id,
    'field': field_name,
    'value': field_value
}))
PYEOF
}

cmd_add_issue() {
    [[ $# -ge 1 ]] || {
        printf 'Usage: %s add-issue <issue_num>\n' "$0" >&2
        exit 2
    }
    local issue_num="$1"
    _require_yaml

    local project_id
    project_id=$(_yaml_get project_id)

    GQ_PROJECT_ID="$project_id" GQ_ISSUE_NUM="$issue_num" \
    GQ_REPO_OWNER="$REPO_OWNER" GQ_REPO_NAME="$REPO_NAME" python3 - <<'PYEOF'
import json, os, subprocess, sys


def gh_api(path):
    r = subprocess.run(['gh', 'api', path], capture_output=True)
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    return json.loads(r.stdout)


def graphql(payload):
    r = subprocess.run(
        ['gh', 'api', 'graphql', '--input', '-'],
        input=json.dumps(payload).encode(),
        capture_output=True
    )
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    resp = json.loads(r.stdout)
    if resp.get('errors'):
        for e in resp['errors']:
            print(e.get('message', str(e)), file=sys.stderr)
        sys.exit(1)
    return resp['data']


project_id = os.environ['GQ_PROJECT_ID']
issue_num = int(os.environ['GQ_ISSUE_NUM'])
owner = os.environ['GQ_REPO_OWNER']
repo = os.environ['GQ_REPO_NAME']

issue_data = gh_api(f'repos/{owner}/{repo}/issues/{issue_num}')
node_id = issue_data['node_id']

data = graphql({
    'query': (
        'mutation($p:ID!,$c:ID!){'
        'addProjectV2ItemById(input:{projectId:$p,contentId:$c}){'
        'item{id}}}'
    ),
    'variables': {'p': project_id, 'c': node_id}
})
new_item_id = data['addProjectV2ItemById']['item']['id']

print(json.dumps({
    'item_id': new_item_id,
    'linked_issue': issue_num
}))
PYEOF
}

cmd_add_pr() {
    [[ $# -ge 1 ]] || {
        printf 'Usage: %s add-pr <pr_num>\n' "$0" >&2
        exit 2
    }
    local pr_num="$1"
    _require_yaml

    local project_id
    project_id=$(_yaml_get project_id)

    GQ_PROJECT_ID="$project_id" GQ_PR_NUM="$pr_num" \
    GQ_REPO_OWNER="$REPO_OWNER" GQ_REPO_NAME="$REPO_NAME" python3 - <<'PYEOF'
import json, os, subprocess, sys


def gh_api(path):
    r = subprocess.run(['gh', 'api', path], capture_output=True)
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    return json.loads(r.stdout)


def graphql(payload):
    r = subprocess.run(
        ['gh', 'api', 'graphql', '--input', '-'],
        input=json.dumps(payload).encode(),
        capture_output=True
    )
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    resp = json.loads(r.stdout)
    if resp.get('errors'):
        for e in resp['errors']:
            print(e.get('message', str(e)), file=sys.stderr)
        sys.exit(1)
    return resp['data']


project_id = os.environ['GQ_PROJECT_ID']
pr_num = int(os.environ['GQ_PR_NUM'])
owner = os.environ['GQ_REPO_OWNER']
repo = os.environ['GQ_REPO_NAME']

pr_data = gh_api(f'repos/{owner}/{repo}/pulls/{pr_num}')
node_id = pr_data['node_id']

data = graphql({
    'query': (
        'mutation($p:ID!,$c:ID!){'
        'addProjectV2ItemById(input:{projectId:$p,contentId:$c}){'
        'item{id}}}'
    ),
    'variables': {'p': project_id, 'c': node_id}
})
new_item_id = data['addProjectV2ItemById']['item']['id']

print(json.dumps({
    'item_id': new_item_id,
    'linked_pr': pr_num
}))
PYEOF
}

cmd_set_pr() {
    [[ $# -ge 2 ]] || {
        printf 'Usage: %s set-pr <item_id> <pr_num>\n' "$0" >&2
        exit 2
    }
    local item_id="$1" pr_num="$2"
    _require_yaml

    local project_id pr_field_id
    project_id=$(_yaml_get project_id)
    pr_field_id=$(_yaml_get pr_field_id)

    GQ_PROJECT_ID="$project_id" GQ_ITEM_ID="$item_id" \
    GQ_FIELD_ID="$pr_field_id" GQ_PR_NUM="$pr_num" python3 - <<'PYEOF'
import json, os, subprocess, sys


def graphql(payload):
    r = subprocess.run(
        ['gh', 'api', 'graphql', '--input', '-'],
        input=json.dumps(payload).encode(),
        capture_output=True
    )
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    resp = json.loads(r.stdout)
    if resp.get('errors'):
        for e in resp['errors']:
            print(e.get('message', str(e)), file=sys.stderr)
        sys.exit(1)
    return resp['data']


project_id = os.environ['GQ_PROJECT_ID']
item_id = os.environ['GQ_ITEM_ID']
field_id = os.environ['GQ_FIELD_ID']
pr_num = os.environ['GQ_PR_NUM']

graphql({
    'query': (
        'mutation($p:ID!,$i:ID!,$f:ID!,$v:String!){'
        'updateProjectV2ItemFieldValue(input:{projectId:$p,itemId:$i,fieldId:$f,'
        'value:{text:$v}}){projectV2Item{id}}}'
    ),
    'variables': {'p': project_id, 'i': item_id, 'f': field_id, 'v': pr_num}
})

print(json.dumps({
    'updated': True,
    'item_id': item_id,
    'pr': pr_num
}))
PYEOF
}

cmd_delete_item() {
    [[ $# -ge 1 ]] || {
        printf 'Usage: %s delete-item <item_id>\n' "$0" >&2
        exit 2
    }
    local item_id="$1"
    _require_yaml

    local project_id
    project_id=$(_yaml_get project_id)

    GQ_PROJECT_ID="$project_id" GQ_ITEM_ID="$item_id" python3 - <<'PYEOF'
import json, os, subprocess, sys


def graphql(payload):
    r = subprocess.run(
        ['gh', 'api', 'graphql', '--input', '-'],
        input=json.dumps(payload).encode(),
        capture_output=True
    )
    if r.returncode != 0:
        print(r.stderr.decode().strip(), file=sys.stderr)
        sys.exit(1)
    resp = json.loads(r.stdout)
    if resp.get('errors'):
        for e in resp['errors']:
            print(e.get('message', str(e)), file=sys.stderr)
        sys.exit(1)
    return resp['data']


project_id = os.environ['GQ_PROJECT_ID']
item_id = os.environ['GQ_ITEM_ID']

data = graphql({
    'query': (
        'mutation($p:ID!,$i:ID!){'
        'deleteProjectV2Item(input:{projectId:$p,itemId:$i}){'
        'deletedItemId}}'
    ),
    'variables': {'p': project_id, 'i': item_id}
})
deleted_id = data['deleteProjectV2Item']['deletedItemId']

print(json.dumps({'deleted_item_id': deleted_id}))
PYEOF
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

subcommand="${1:-}"
[[ -n "$subcommand" ]] || _usage
shift

case "$subcommand" in
    create-draft)   cmd_create_draft "$@" ;;
    list-by-status) cmd_list_by_status "$@" ;;
    get-item)       cmd_get_item "$@" ;;
    update-field)   cmd_update_field "$@" ;;
    add-issue)      cmd_add_issue "$@" ;;
    add-pr)         cmd_add_pr "$@" ;;
    set-pr)         cmd_set_pr "$@" ;;
    delete-item)    cmd_delete_item "$@" ;;
    *)
        printf 'Error: unknown subcommand: %s\n' "$subcommand" >&2
        _usage
        ;;
esac
