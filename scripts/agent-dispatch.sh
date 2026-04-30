#!/usr/bin/env bash
# Helper for /dispatch and /isoagents skills.
# Wraps commands that contain $() or Go-template quotes so Claude Code
# can invoke them without triggering manual-approval prompts.
set -euo pipefail

REPO_ROOT="${CFGMS_TEST_REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
WORKTREE_BASE="${CFGMS_TEST_WORKTREE_BASE:-$(cd "$REPO_ROOT/.." && pwd)/worktrees}"

# Ensure clone is based on latest remote develop, not stale local state.
# Called inside fresh clones after setting the remote URL.
sync_to_remote_develop() {
  git fetch origin develop
  git reset --hard origin/develop
}

# Validate branch name: only allow safe characters (alphanumeric, /, -, ., _)
validate_branch() {
  local branch="$1"
  if [[ ! "$branch" =~ ^[a-zA-Z0-9/_.-]+$ ]]; then
    echo "ERROR: Invalid branch name '${branch}'. Only alphanumeric, '/', '-', '.', and '_' are allowed."
    exit 1
  fi
}

# Sanitize branch name for use in container/directory names: / → --
sanitize_branch() {
  echo "$1" | sed 's|/|--|g'
}

# Emit OPEN_PR_EXISTS:<ISSUE>:<PR>:<TITLE> for each open PR that references
# this issue. Uses two signals:
#   1. GitHub's authoritative "closing PR" linkage (body Fixes/Closes/Resolves
#      or manual UI link) via the issue.closedByPullRequestsReferences field
#   2. Title-pattern fallback: "(Issue #<N>)" or "#<N>" in an open PR title,
#      which catches agent PRs whose bodies omit the Fixes keyword
check_existing_prs_for_issue() {
  local issue_num="$1"
  # Test hook: canned output for hermetic unit tests. Format is newline-separated
  # OPEN_PR_EXISTS:<issue>:<pr>:<title> lines (empty = no conflicts).
  if [[ -n "${CFGMS_TEST_MOCK_EXISTING_PRS:-}" ]]; then
    printf '%s\n' "${CFGMS_TEST_MOCK_EXISTING_PRS}" | grep -E "^OPEN_PR_EXISTS:${issue_num}:" || true
    return 0
  fi
  local graphql_out title_out
  # Authoritative linkage via GraphQL (closing-PR references: body Fixes/Closes/Resolves or manual UI link).
  # Non-existent issues return an error; we swallow it and produce no output.
  graphql_out=$(gh api graphql -f query="
      query(\$num: Int!) {
        repository(owner: \"cfg-is\", name: \"cfgms\") {
          issue(number: \$num) {
            closedByPullRequestsReferences(first: 20, includeClosedPrs: false) {
              nodes { number title state }
            }
          }
        }
      }" -F num="$issue_num" --jq '
        .data.repository.issue.closedByPullRequestsReferences.nodes[]?
        | select(.state == "OPEN")
        | "OPEN_PR_EXISTS:'"$issue_num"':\(.number):\(.title | gsub(":"; " "))"
      ' 2>/dev/null) || graphql_out=""
  # Title-pattern fallback for PRs that reference the issue without Fixes keyword.
  title_out=$(gh pr list --repo cfg-is/cfgms --state open --limit 50 \
        --search "in:title #${issue_num}" \
        --json number,title --jq '
      .[] | "OPEN_PR_EXISTS:'"$issue_num"':\(.number):\(.title | gsub(":"; " "))"
    ' 2>/dev/null || true)
  printf '%s\n%s\n' "$graphql_out" "$title_out" | grep -v '^$' | sort -u || true
  return 0
}

# Refresh agent credentials from the host's Claude session.
# Copies ~/.claude/.credentials.json into the claude-creds Docker volume
# so agents always start with a fresh token. No interactive OAuth needed.
refresh_creds_from_host() {
  local host_creds="$HOME/.claude/.credentials.json"
  if [ ! -f "$host_creds" ]; then
    echo "WARN: No host credentials at $host_creds — agents may fail auth"
    return 0
  fi
  docker run --rm --entrypoint bash \
    -v claude-creds:/persist \
    -v "$host_creds:/host-creds.json:ro" \
    cfg-agent:latest \
    -c "cp /host-creds.json /persist/.credentials.json" 2>/dev/null \
    && echo "Refreshed agent credentials from host session" \
    || echo "WARN: Failed to refresh credentials from host"
}

usage() {
  cat <<'EOF'
Usage: agent-dispatch.sh <command> [args...]

Commands:
  check-conflicts <NUM> [NUM...]            Check for existing containers/clones (issue mode)
  check-conflicts --branch <NAME>           Check for existing containers/clones (branch mode)
  check-conflicts --pr <NUM>                Check for existing containers/clones (PR-fix mode)
  create-clone    <NUM> [--keep-remote] [--allow-duplicate-pr]
                                            Clone repo and create feature branch (issue mode)
                                            If remote branch feature/story-<NUM>-agent already exists,
                                            it is force-deleted before the fresh branch is created.
                                            Pass --keep-remote to preserve the stale branch (forensics).
                                            Refuses to dispatch if an open PR already references the
                                            issue via Fixes/Closes/Resolves (exit 2). Pass
                                            --allow-duplicate-pr to override for parallel-work cases.
  create-clone-branch <BRANCH>              Clone repo and checkout/create branch
  create-clone-pr <PR_NUM>                  Clone repo and checkout PR branch
  launch          <NUM>                     Launch agent container (issue mode)
  launch-generic  <NAME> <DIR> [ARGS...]    Launch agent container with custom name and args
  live            <BRANCH|NUM>               Drop into live Claude session (branch name or issue number)
  po-live         [PO_ARGS...]               Drop into live Claude session pre-seeded with /po <args> (intent capture, planning team, etc.)
  launch-interactive <BRANCH>               Print docker run command for interactive session
  wait-for-auth   <NUM> [NUM...]            (deprecated, no-op) Legacy auth polling
  wait-for-auth   --container <NAME> [...]  (deprecated, no-op) Legacy auth polling
  check-creds                                Check OAuth credential validity and remaining time
  cleanup-issue   <NUM>                     Remove container and clone for a specific issue
  cleanup-container <NAME>                  Remove container and associated clone by name
  cleanup-stale                             Remove containers/clones for closed, blocked, or failed stories
  list-running                              List running agent containers
  list-exited                               List exited agent containers
  inspect-exit    <NUM>                     Print exit code of container
  inspect-detail  <NUM>                     Print stats + last 30 log lines
  inspect-container <NAME>                  Print stats + last 30 log lines for named container
  health-check                              Check image age, Claude version, creds staleness
EOF
  exit 1
}

[[ $# -ge 1 ]] || usage

cmd="$1"; shift

case "$cmd" in

  check-conflicts)
    [[ $# -ge 1 ]] || { echo "check-conflicts requires arguments"; exit 1; }
    case "$1" in
      --branch)
        [[ $# -ge 2 ]] || { echo "check-conflicts --branch requires a branch name"; exit 1; }
        branch="$2"
        validate_branch "$branch"
        sanitized=$(sanitize_branch "$branch")
        container_name="cfg-agent-branch-${sanitized}"
        clone_dir="${WORKTREE_BASE}/${sanitized}"
        existing=$(docker ps -a --filter "name=${container_name}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
        if [[ -n "$existing" ]]; then
          echo "CONTAINER_EXISTS:${branch}:${existing}"
        fi
        if [[ -d "$clone_dir" ]]; then
          echo "CLONE_EXISTS:${branch}:${clone_dir}"
        fi
        echo "CHECK_DONE"
        ;;
      --pr)
        [[ $# -ge 2 ]] || { echo "check-conflicts --pr requires a PR number"; exit 1; }
        pr_num="$2"
        container_name="cfg-agent-pr-fix-${pr_num}"
        clone_dir="${WORKTREE_BASE}/pr-fix-${pr_num}"
        existing=$(docker ps -a --filter "name=${container_name}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
        if [[ -n "$existing" ]]; then
          echo "CONTAINER_EXISTS:pr-${pr_num}:${existing}"
        fi
        if [[ -d "$clone_dir" ]]; then
          echo "CLONE_EXISTS:pr-${pr_num}:${clone_dir}"
        fi
        echo "CHECK_DONE"
        ;;
      *)
        # Original issue-number mode
        for num in "$@"; do
          existing=$(docker ps -a --filter "name=cfg-agent-${num}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
          if [[ -n "$existing" ]]; then
            echo "CONTAINER_EXISTS:${num}:${existing}"
          fi
          if [[ -d "${WORKTREE_BASE}/story-${num}" ]]; then
            echo "CLONE_EXISTS:${num}:${WORKTREE_BASE}/story-${num}"
          fi
          check_existing_prs_for_issue "$num"
        done
        echo "CHECK_DONE"
        ;;
    esac
    ;;

  create-clone)
    keep_remote=false
    allow_duplicate_pr=false
    while [[ $# -gt 0 && "$1" == --* ]]; do
      case "$1" in
        --keep-remote) keep_remote=true; shift ;;
        --allow-duplicate-pr) allow_duplicate_pr=true; shift ;;
        *) echo "Unknown flag for create-clone: $1"; exit 1 ;;
      esac
    done
    [[ $# -eq 1 ]] || { echo "create-clone requires exactly one issue number"; exit 1; }
    num="$1"
    branch_name="feature/story-${num}-agent"
    dest="${WORKTREE_BASE}/story-${num}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Refuse to dispatch if an open PR already references this issue via
    # Fixes/Closes/Resolves. Override with --allow-duplicate-pr for genuine
    # parallel-work cases. Prevents wasted agent cycles on already-solved bugs.
    if ! $allow_duplicate_pr; then
      existing_pr_lines=$(check_existing_prs_for_issue "$num")
      if [[ -n "$existing_pr_lines" ]]; then
        echo "$existing_pr_lines"
        echo "ERROR: Open PR(s) already reference issue #${num}. Refusing to dispatch duplicate work."
        echo "       Review and merge/close the existing PR, or re-run with --allow-duplicate-pr."
        exit 2
      fi
    fi

    # Check for stale remote branch before cloning. A stale branch causes history
    # corruption when the new container pushes (git merges the two histories).
    if git -C "$REPO_ROOT" ls-remote --heads origin "$branch_name" 2>/dev/null | grep -q .; then
      if $keep_remote; then
        echo "INFO: Stale remote branch exists: ${branch_name} (keeping due to --keep-remote)"
      else
        echo "Cleaning stale remote branch: ${branch_name}"
        if ! git -C "$REPO_ROOT" push origin --delete "$branch_name" 2>&1; then
          echo "ERROR: Failed to delete stale remote branch '${branch_name}'. Refusing to dispatch to prevent history corruption."
          exit 1
        fi
      fi
    fi

    trap "rm -rf '$dest'" ERR
    git clone --local --branch develop "$REPO_ROOT" "$dest"
    cd "$dest"
    git remote set-url origin "$github_url"
    sync_to_remote_develop
    git checkout -b "$branch_name"
    trap - ERR
    echo "CLONE_OK:${num}:$(git branch --show-current)"
    ;;

  create-clone-branch)
    [[ $# -eq 1 ]] || { echo "create-clone-branch requires exactly one branch name"; exit 1; }
    branch="$1"
    validate_branch "$branch"
    sanitized=$(sanitize_branch "$branch")
    dest="${WORKTREE_BASE}/${sanitized}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Check if branch exists on remote
    trap "rm -rf '$dest'" ERR
    if git -C "$REPO_ROOT" ls-remote --heads origin "$branch" | grep -q .; then
      # Branch exists: clone develop, then fetch and checkout the branch
      git clone --local --branch develop "$REPO_ROOT" "$dest"
      cd "$dest"
      git remote set-url origin "$github_url"
      sync_to_remote_develop
      git fetch origin "$branch"
      git checkout "$branch"
      trap - ERR
      echo "CLONE_OK:${sanitized}:${branch}"
    else
      # Branch does not exist: clone develop, create new branch
      git clone --local --branch develop "$REPO_ROOT" "$dest"
      cd "$dest"
      git remote set-url origin "$github_url"
      sync_to_remote_develop
      git checkout -b "$branch"
      trap - ERR
      echo "CLONE_NEW:${sanitized}:${branch}"
    fi
    ;;

  create-clone-pr)
    [[ $# -eq 1 ]] || { echo "create-clone-pr requires exactly one PR number"; exit 1; }
    pr_num="$1"
    dest="${WORKTREE_BASE}/pr-fix-${pr_num}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Get branch from PR
    pr_branch=$(gh pr view "$pr_num" --json headRefName -q '.headRefName' 2>/dev/null) || {
      echo "ERROR: Failed to get branch for PR #${pr_num}"
      exit 1
    }

    # Extract issue number from PR body
    pr_body=$(gh pr view "$pr_num" --json body -q '.body' 2>/dev/null || echo "")
    issue_num=$(echo "$pr_body" | grep -oP 'Fixes #\K[0-9]+' | head -1 || true)
    if [[ -z "$issue_num" ]] && [[ "$pr_branch" =~ story-([0-9]+) ]]; then
      issue_num="${BASH_REMATCH[1]}"
    fi

    # Clone and checkout the PR branch
    trap "rm -rf '$dest'" ERR
    git clone --local --branch develop "$REPO_ROOT" "$dest"
    cd "$dest"
    git remote set-url origin "$github_url"
    sync_to_remote_develop
    git fetch origin "$pr_branch"
    git checkout "$pr_branch"
    trap - ERR

    echo "CLONE_OK:pr-fix-${pr_num}:${pr_branch}:issue=${issue_num:-none}"
    ;;

  launch)
    [[ $# -eq 1 ]] || { echo "launch requires exactly one issue number"; exit 1; }
    num="$1"
    clone_path="${WORKTREE_BASE}/story-${num}"
    real_path=$(realpath "$clone_path")
    refresh_creds_from_host
    gh_token=$(gh auth token)
    if container_id=$(docker run -d \
      --name "cfg-agent-${num}" \
      --label "cfg-agent=true" \
      --label "issue=${num}" \
      --label "mode=issue" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "claude-creds:/persist" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${num}" 2>&1); then
      echo "LAUNCHED:${num}:${container_id}"
    else
      # Launch failed — clean up orphaned clone to prevent blocking future dispatches
      echo "LAUNCH_FAILED:${num}:${container_id}"
      rm -rf "$clone_path"
      echo "CLEANED:clone:${clone_path}"
      exit 1
    fi
    ;;

  launch-generic)
    [[ $# -ge 2 ]] || { echo "launch-generic requires <CONTAINER_NAME> <CLONE_DIR> [ENTRYPOINT_ARGS...]"; exit 1; }
    container_name="$1"; shift
    clone_dir="$1"; shift
    entrypoint_args=("$@")

    real_path=$(realpath "$clone_dir")
    refresh_creds_from_host
    gh_token=$(gh auth token)

    # Derive mode and metadata labels from entrypoint args
    mode_label="branch"
    extra_labels=()
    for i in "${!entrypoint_args[@]}"; do
      case "${entrypoint_args[$i]}" in
        --fix-pr) mode_label="fix-pr"; extra_labels+=(--label "pr=${entrypoint_args[$((i+1))]}") ;;
        --branch) extra_labels+=(--label "branch=${entrypoint_args[$((i+1))]}") ;;
        --issue)  extra_labels+=(--label "issue=${entrypoint_args[$((i+1))]}") ;;
      esac
    done

    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=${mode_label}" \
      "${extra_labels[@]}" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "claude-creds:/persist" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${entrypoint_args[@]}" 2>&1); then
      echo "LAUNCHED:${container_name}:${container_id}"
    else
      echo "LAUNCH_FAILED:${container_name}:${container_id}"
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
      exit 1
    fi
    ;;

  live)
    [[ $# -ge 1 ]] || { echo "live requires a branch name or issue number"; exit 1; }
    target="$1"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Determine branch and clone dir based on target type
    if [[ "$target" =~ ^[0-9]+$ ]]; then
      # Issue number: look for existing branch, or create one
      num="$target"
      # Check for existing feature branch on remote (agent or non-agent)
      existing_branch=$(git -C "$REPO_ROOT" ls-remote --heads origin "feature/story-${num}-*" 2>/dev/null | head -1 | sed 's|.*refs/heads/||')
      if [[ -n "$existing_branch" ]]; then
        branch="$existing_branch"
        echo "Found existing branch: ${branch}"
      else
        branch="feature/story-${num}"
        echo "No existing branch — will create: ${branch}"
      fi
      clone_dir="${WORKTREE_BASE}/story-${num}"
    else
      # Branch name
      branch="$target"
      validate_branch "$branch"
      clone_dir="${WORKTREE_BASE}/$(sanitize_branch "$branch")"
    fi

    sanitized=$(sanitize_branch "$branch")
    container_name="cfg-agent-live-${sanitized}"

    # Create clone from develop with branch (or reuse existing clone)
    if [[ -d "$clone_dir" ]]; then
      echo "Clone already exists at ${clone_dir}, reusing"
    else
      trap "rm -rf '$clone_dir'" ERR
      if git -C "$REPO_ROOT" ls-remote --heads origin "$branch" | grep -q .; then
        git clone --local --branch develop "$REPO_ROOT" "$clone_dir"
        cd "$clone_dir"
        git remote set-url origin "$github_url"
        sync_to_remote_develop
        git fetch origin "$branch"
        git checkout "$branch"
      else
        git clone --local --branch develop "$REPO_ROOT" "$clone_dir"
        cd "$clone_dir"
        git remote set-url origin "$github_url"
        sync_to_remote_develop
        git checkout -b "$branch"
      fi
      trap - ERR
    fi

    real_path=$(realpath "$clone_dir")
    refresh_creds_from_host
    gh_token=$(gh auth token)

    # Remove stale container with the same name if it exists
    docker rm -f "$container_name" 2>/dev/null || true

    echo "================================================"
    echo " CFGMS Live Session"
    echo " Branch: ${branch}"
    echo " Clone:  ${real_path}"
    echo "================================================"

    # Mount the host's ~/.claude directly so interactive claude shares the
    # host's auth state — no login prompt, no credential dance.
    host_claude_dir="$HOME/.claude"
    host_claude_json="$HOME/.claude.json"

    exec docker run -it --rm \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=live" \
      --label "branch=${branch}" \
      --memory=4g \
      --cpus=4 \
      -v "${real_path}:/workspace" \
      -v "${host_claude_dir}:/home/agent/.claude" \
      -v "${host_claude_json}:/home/agent/.claude.json" \
      -v "${REPO_ROOT}/.devcontainer/scripts/setup-env.sh:/usr/local/bin/setup-env.sh:ro" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_AGENT_MODE=true" \
      -e "GOMODCACHE=/home/agent/go/pkg/mod" \
      -e "GOFLAGS=-modcacherw" \
      --cap-add NET_ADMIN \
      --entrypoint /bin/bash \
      cfg-agent:latest \
      -c "setup-env.sh && exec claude --dangerously-skip-permissions"
    ;;

  po-live)
    # Launch an interactive PO session in a docker container, pre-seeded with
    # /po <args> so the conversation is already in role. All args are joined
    # and passed as the initial prompt; e.g. `po-live intent certificate
    # rotation` opens a session with first message `/po intent certificate
    # rotation`. With no args the session opens at `/po` (dashboard).
    #
    # Interactive shell required: docker run -it needs a real TTY.
    # If invoked from inside tmux and POLIVE_INNER is unset, this command
    # splits a new pane to the right and re-invokes itself there with
    # POLIVE_INNER=1 set, so the docker run lands in the new pane.
    # If invoked outside tmux, the script refuses (the slash command should
    # have detected this upfront and fallen back to /po).
    if [[ -n "$TMUX" && -z "${POLIVE_INNER:-}" ]]; then
      # Build the re-invocation as a single quoted command. Use printf %q to
      # safely escape each arg (handles spaces, quotes, slashes in topics).
      escaped=""
      for a in "$@"; do
        escaped+=" $(printf '%q' "$a")"
      done
      exec tmux split-window -h "POLIVE_INNER=1 $0 po-live${escaped}"
    fi

    if [[ -z "$TMUX" && -z "${POLIVE_INNER:-}" ]]; then
      echo "ERROR: po-live requires an interactive tmux session (docker run -it needs a real TTY)." >&2
      echo "       Run this command from a tmux pane, OR use /po inline if you can't open one." >&2
      exit 1
    fi

    args="$*"
    container_name="cfg-agent-live-po"
    clone_dir="${WORKTREE_BASE}/po-live"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Reuse or create the shared po-live clone (PO sessions don't edit code,
    # so a single shared workspace on develop is fine).
    if [[ -d "$clone_dir" ]]; then
      echo "Clone already exists at ${clone_dir}, reusing"
    else
      trap "rm -rf '$clone_dir'" ERR
      git clone --local --branch develop "$REPO_ROOT" "$clone_dir"
      cd "$clone_dir"
      git remote set-url origin "$github_url"
      sync_to_remote_develop
      trap - ERR
    fi

    real_path=$(realpath "$clone_dir")
    refresh_creds_from_host
    gh_token=$(gh auth token)

    # Remove stale container with the same name (only one PO live at a time)
    docker rm -f "$container_name" 2>/dev/null || true

    # Build the initial prompt without trailing space when args are empty.
    # Trailing space leaves Claude's input box mid-word and shows the slash-
    # command autocomplete dropdown instead of submitting on Enter.
    if [[ -n "$args" ]]; then
      po_prompt="/po ${args}"
      po_name="PO: ${args}"
    else
      po_prompt="/po"
      po_name="PO"
    fi

    echo "================================================"
    echo " CFGMS PO Live Session"
    echo " Initial prompt: ${po_prompt}"
    echo " Clone:          ${real_path}"
    echo "================================================"

    host_claude_dir="$HOME/.claude"
    host_claude_json="$HOME/.claude.json"

    # Pass $1 (display name) and $2 (initial prompt) via bash -c positional
    # args to avoid shell-quote escaping pain when args contain special chars.
    exec docker run -it --rm \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=po-live" \
      --memory=4g \
      --cpus=4 \
      -v "${real_path}:/workspace" \
      -v "${host_claude_dir}:/home/agent/.claude" \
      -v "${host_claude_json}:/home/agent/.claude.json" \
      -v "${REPO_ROOT}/.devcontainer/scripts/setup-env.sh:/usr/local/bin/setup-env.sh:ro" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      -e "GOMODCACHE=/home/agent/go/pkg/mod" \
      -e "GOFLAGS=-modcacherw" \
      --cap-add NET_ADMIN \
      --entrypoint /bin/bash \
      cfg-agent:latest \
      -c 'setup-env.sh && exec claude --dangerously-skip-permissions --name "$1" "$2"' \
      cfg-agent-live-po \
      "$po_name" \
      "$po_prompt"
    ;;

  launch-interactive)
    [[ $# -ge 1 ]] || { echo "launch-interactive requires a branch name and optional clone dir"; exit 1; }
    branch="$1"
    validate_branch "$branch"
    sanitized=$(sanitize_branch "$branch")
    clone_dir="${2:-${WORKTREE_BASE}/${sanitized}}"
    real_path=$(realpath "$clone_dir")
    refresh_creds_from_host
    gh_token=$(gh auth token)
    container_name="cfg-agent-interactive-${sanitized}"

    # Use setup-env.sh for shared setup (firewall, credential symlinks, git config).
    # setup-env.sh is baked into the image at /usr/local/bin/ so it works even when
    # the cloned branch doesn't contain our tooling files.
    setup_cmds="setup-env.sh"
    setup_cmds+=" && echo '================================================'"
    setup_cmds+=" && echo ' CFGMS Interactive Agent Session'"
    setup_cmds+=" && echo ' Branch: ${branch}'"
    setup_cmds+=" && echo ' Starting remote-control server...'"
    setup_cmds+=" && echo ' Connect at: https://claude.ai/code'"
    setup_cmds+=" && echo '================================================'"
    setup_cmds+=" && echo 'Warming up workspace trust...'"
    setup_cmds+=" && claude -p 'ready' --dangerously-skip-permissions 2>&1 || echo 'WARN: trust warmup failed (non-fatal)'"
    setup_cmds+=" && echo 'Starting remote-control...'"
    setup_cmds+=" && exec claude remote-control --permission-mode bypassPermissions --name '${branch}' 2>&1"

    # Launch container in detached mode with remote-control server
    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=interactive" \
      --label "branch=${branch}" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "claude-creds:/persist" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_AGENT_MODE=true" \
      --cap-add NET_ADMIN \
      --entrypoint /bin/bash \
      cfg-agent:latest \
      -c "$setup_cmds" 2>&1); then
      echo "LAUNCHED:${container_name}:${container_id}"
      echo ""
      echo "Interactive session starting with remote-control mode."
      echo "Connect from your browser at: https://claude.ai/code"
      echo "Look for session named: ${branch}"
      echo ""
      echo "To view the session URL and QR code:"
      echo "  docker logs ${container_name}"
      echo ""
      echo "To drop into a shell inside the container:"
      echo "  docker exec -it ${container_name} bash"
    else
      echo "LAUNCH_FAILED:${container_name}:${container_id}"
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
      exit 1
    fi
    ;;

  wait-for-auth)
    # Deprecated: credentials are now pre-validated via check-creds and copied
    # from the host via refresh_creds_from_host before launch. This no-op
    # preserves backward compatibility for any callers that still invoke it.
    echo "WAIT_DONE"
    ;;

  check-creds)
    # Refresh from host session first so we check what agents will actually use
    refresh_creds_from_host >/dev/null 2>&1
    # Then check OAuth credential validity in the shared volume
    if ! docker volume inspect claude-creds >/dev/null 2>&1; then
      echo "CREDS_MISSING:no claude-creds volume"
    elif ! docker run --rm -v claude-creds:/persist --entrypoint test cfg-agent:latest -f /persist/.credentials.json 2>/dev/null; then
      echo "CREDS_MISSING:no credentials file"
    else
      result=$(docker run --rm -v claude-creds:/persist --entrypoint python3 cfg-agent:latest -c "
import json, time
d = json.load(open('/persist/.credentials.json'))
oauth = d.get('claudeAiOauth', {})
exp_ms = oauth.get('expiresAt', 0)
exp_s = exp_ms / 1000
now = time.time()
remaining_min = int((exp_s - now) / 60)
if remaining_min < 0:
    print(f'CREDS_EXPIRED:{remaining_min}')
elif remaining_min < 15:
    print(f'CREDS_LOW:{remaining_min}')
else:
    print(f'CREDS_OK:{remaining_min}')
" 2>/dev/null || echo "CREDS_ERROR:failed to parse")
      echo "$result"
    fi
    ;;

  cleanup-issue)
    [[ $# -eq 1 ]] || { echo "cleanup-issue requires exactly one issue number"; exit 1; }
    num="$1"
    # Copy result file (best-effort)
    docker cp "cfg-agent-${num}:/tmp/agent-result.json" "/tmp/agent-result-${num}.json" 2>/dev/null || true
    # Remove container (works for both running and exited)
    if docker rm -f "cfg-agent-${num}" >/dev/null 2>&1; then
      echo "CLEANED:container:cfg-agent-${num}"
    else
      echo "SKIP:container:cfg-agent-${num} not found"
    fi
    # Remove clone directory
    clone_dir="${WORKTREE_BASE}/story-${num}"
    if [[ -d "$clone_dir" ]]; then
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
    else
      echo "SKIP:clone:${clone_dir} not found"
    fi
    echo "CLEANUP_DONE:${num}"
    ;;

  cleanup-container)
    [[ $# -eq 1 ]] || { echo "cleanup-container requires exactly one container name"; exit 1; }
    container_name="$1"
    # Copy result file (best-effort)
    docker cp "${container_name}:/tmp/agent-result.json" "/tmp/agent-result-${container_name}.json" 2>/dev/null || true
    # Remove container
    if docker rm -f "$container_name" >/dev/null 2>&1; then
      echo "CLEANED:container:${container_name}"
    else
      echo "SKIP:container:${container_name} not found"
    fi
    # Derive clone directory from container name
    clone_dir=""
    if [[ "$container_name" =~ ^cfg-agent-pr-fix-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/pr-fix-${BASH_REMATCH[1]}"
    elif [[ "$container_name" =~ ^cfg-agent-branch-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/${BASH_REMATCH[1]}"
    elif [[ "$container_name" =~ ^cfg-agent-interactive-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/${BASH_REMATCH[1]}"
    fi
    if [[ -n "$clone_dir" ]] && [[ -d "$clone_dir" ]]; then
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
    elif [[ -n "$clone_dir" ]]; then
      echo "SKIP:clone:${clone_dir} not found"
    fi
    echo "CLEANUP_DONE:${container_name}"
    ;;

  list-running)
    docker ps --filter "label=cfg-agent=true" \
      --format "{{.Names}}\t{{.Status}}\t{{.Label \"issue\"}}\t{{.Label \"mode\"}}\t{{.Label \"branch\"}}\t{{.Label \"pr\"}}" 2>/dev/null || true
    ;;

  list-exited)
    docker ps -a --filter "label=cfg-agent=true" --filter "status=exited" \
      --format "{{.Names}}\t{{.Label \"issue\"}}\t{{.Label \"mode\"}}\t{{.Label \"branch\"}}\t{{.Label \"pr\"}}" 2>/dev/null || true
    ;;

  inspect-exit)
    [[ $# -eq 1 ]] || { echo "inspect-exit requires exactly one issue number"; exit 1; }
    docker inspect --format "{{.State.ExitCode}}" "cfg-agent-$1"
    ;;

  inspect-detail)
    [[ $# -eq 1 ]] || { echo "inspect-detail requires exactly one issue number"; exit 1; }
    echo "=== Stats ==="
    docker stats --no-stream "cfg-agent-$1" 2>/dev/null || echo "(container not running)"
    echo "=== Last 30 log lines ==="
    docker logs --tail 30 "cfg-agent-$1" 2>/dev/null || echo "(no logs available)"
    ;;

  inspect-container)
    [[ $# -eq 1 ]] || { echo "inspect-container requires exactly one container name"; exit 1; }
    echo "=== Stats ==="
    docker stats --no-stream "$1" 2>/dev/null || echo "(container not running)"
    echo "=== Last 30 log lines ==="
    docker logs --tail 30 "$1" 2>/dev/null || echo "(no logs available)"
    ;;

  health-check)
    warnings=0

    # Image age check (warn if >7 days)
    created=$(docker inspect cfg-agent:latest --format "{{.Created}}" 2>/dev/null || true)
    if [[ -z "$created" ]]; then
      echo "WARN:image:Image cfg-agent:latest not found — run /agent-setup"
      warnings=$((warnings + 1))
    else
      created_epoch=$(date -d "$created" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "${created%%.*}" +%s 2>/dev/null || echo 0)
      now_epoch=$(date +%s)
      age_days=$(( (now_epoch - created_epoch) / 86400 ))
      echo "INFO:image_age:${age_days} days old (built ${created%%T*})"
      if [[ $age_days -ge 7 ]]; then
        echo "WARN:image_age:Image is ${age_days} days old — Trivy DB and Go modules may be stale. Run /agent-setup rebuild"
        warnings=$((warnings + 1))
      fi
    fi

    # Claude version comparison
    host_version=$(claude --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "unknown")
    container_version=$(docker run --rm --entrypoint claude cfg-agent:latest --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "unknown")
    echo "INFO:claude_version:host=${host_version} container=${container_version}"
    if [[ "$host_version" != "unknown" && "$container_version" != "unknown" && "$host_version" != "$container_version" ]]; then
      echo "WARN:claude_version:Host Claude (${host_version}) differs from container (${container_version}). Run /agent-setup rebuild"
      warnings=$((warnings + 1))
    fi

    # Credentials check
    if docker run --rm -v claude-creds:/persist --entrypoint test cfg-agent:latest -f /persist/.credentials.json 2>/dev/null; then
      echo "INFO:creds:Credentials present in claude-creds volume"
    else
      echo "WARN:creds:No credentials found — run /agent-setup creds"
      warnings=$((warnings + 1))
    fi

    echo "HEALTH_DONE:warnings=${warnings}"
    ;;

  cleanup-stale)
    # Find agent containers (running or exited) whose stories no longer need them.
    # A container is stale if its story issue is CLOSED or has label agent:failed or pipeline:blocked.
    cleaned=0

    # Get all cfg-agent-<NUM> containers (running + exited)
    containers=$(docker ps -a --filter "label=cfg-agent=true" --format "{{.Names}}" 2>/dev/null || true)

    for container_name in $containers; do
      # Extract issue number from container name (cfg-agent-<NUM>)
      if [[ "$container_name" =~ ^cfg-agent-([0-9]+)$ ]]; then
        num="${BASH_REMATCH[1]}"
      else
        # Skip non-issue containers (pr-fix, branch, interactive)
        continue
      fi

      # Check issue state and labels
      issue_json=$(gh issue view "$num" --repo cfg-is/cfgms --json state,labels 2>/dev/null || echo '{"state":"UNKNOWN","labels":[]}')
      state=$(echo "$issue_json" | grep -oP '"state"\s*:\s*"\K[^"]+' || echo "UNKNOWN")
      labels=$(echo "$issue_json" | grep -oP '"name"\s*:\s*"\K[^"]+' || true)

      should_clean=false

      # Clean if story is closed (merged or manually closed)
      if [[ "$state" == "CLOSED" ]]; then
        should_clean=true
        reason="story closed"
      fi

      # Clean if story is failed or blocked (agent is done, needs human intervention)
      if echo "$labels" | grep -q "agent:failed"; then
        should_clean=true
        reason="agent:failed"
      fi
      if echo "$labels" | grep -q "pipeline:blocked"; then
        should_clean=true
        reason="pipeline:blocked"
      fi

      if $should_clean; then
        echo "STALE:${num}:${reason}"
        # Reuse cleanup-issue logic
        docker cp "cfg-agent-${num}:/tmp/agent-result.json" "/tmp/agent-result-${num}.json" 2>/dev/null || true
        if docker rm -f "cfg-agent-${num}" >/dev/null 2>&1; then
          echo "CLEANED:container:cfg-agent-${num}"
        fi
        clone_dir="${WORKTREE_BASE}/story-${num}"
        if [[ -d "$clone_dir" ]]; then
          rm -rf "$clone_dir"
          echo "CLEANED:clone:${clone_dir}"
        fi
        cleaned=$((cleaned + 1))
      fi
    done

    echo "CLEANUP_STALE_DONE:cleaned=${cleaned}"
    ;;

  *)
    echo "Unknown command: $cmd"
    usage
    ;;
esac
