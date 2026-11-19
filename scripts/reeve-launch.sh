#!/usr/bin/env bash
# reeve-launch.sh — start, stop or show the Reeve container.
#
# Reeve is the agent the founder talks to. Its definition is
# .claude/agents/reeve.md in cfgms. This script runs on the host.
#
#   reeve-launch.sh start [--continue | --resume <session-id>]
#   reeve-launch.sh stop
#   reeve-launch.sh status
#   reeve-launch.sh screen      print what is on Reeve's screen now
#
# What Reeve gets:
#   /workspace/cfgms                read-only clone of develop, with tooling
#   /workspace/cfgms-canon          read-write (the host clone)
#   /workspace/cfgms-memory         read-only  (the host clone)
#   /workspace/claude-code-memory   read-only  (the founder's Claude Code memory files)
#   /run/reeve-tokens/canon.token   contents:write on cfgms-canon only
#   /run/reeve-tokens/cfgms.token   issues on cfgms only, plus the
#                                   organization's project boards (that
#                                   permission is not per repository)
#
# The GitHub App key never enters the container. GitHub App tokens live one
# hour, so a host loop makes new ones every 45 minutes while the container
# runs. When the container stops, the loop revokes the tokens, deletes the
# token files and exits. Token files are kept on tmpfs ($XDG_RUNTIME_DIR), not
# on disk.
#
# Host settings (each has an environment variable; see below):
#   ~/.config/cfgms/reeve.conf          two lines: app_id=<number> and
#                                       installation_id=<number> of the GitHub
#                                       App that makes Reeve's tokens
#   ~/.config/cfgms/reeve-app-key.cred  the App key, sealed with systemd-creds
#
# Know before you use it: Reeve gets the host's ~/.claude and ~/.claude.json
# read-write (the founder's full Claude login, as po-live does) and runs with
# no permission prompts. So Reeve is trusted like the founder's own Claude
# session: a file it writes into ~/.claude can run on the host later. The
# mounts and the two tokens limit what it does to GitHub, not to this host.
#
# The host never runs git in cfgms-canon: the container can write that
# clone's .git/config, and a config line (a filter, a credential helper) is a
# program for the git that reads it. The container checks and updates canon
# itself (reeve-container-setup.sh). The host does not update cfgms-memory
# either; it is mounted as it is.
set -euo pipefail

CFG_ROOT="${CFGMS_REEVE_ROOT:-$HOME/git/cfg.is}"
CFGMS_REPO="${CFGMS_REEVE_CFGMS_REPO:-$CFG_ROOT/cfgms}"
CANON_DIR="${CFGMS_REEVE_CANON_DIR:-$CFG_ROOT/cfgms-canon}"
MEMORY_DIR="${CFGMS_REEVE_MEMORY_DIR:-$CFG_ROOT/cfgms-memory}"
# Claude Code names a project's folder after the project path, with each "/"
# and "." replaced by "-".
CC_MEMORY_DIR="${CFGMS_REEVE_CC_MEMORY:-$HOME/.claude/projects/$(printf '%s' "$CFGMS_REPO" | tr '/.' '--')/memory}"
CONTAINER_SETUP="${CFGMS_REEVE_CONTAINER_SETUP:-$(dirname "$(realpath "$0")")/reeve-container-setup.sh}"

STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/cfgms/reeve"
TOKEN_DIR="${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is not set}/cfgms-reeve"
# The agent definition comes from the launcher's own clone of cfgms develop
# (made by prepare_cfgms_clone), so Reeve runs the merged definition.
REEVE_DEF="${CFGMS_REEVE_DEF:-$STATE_DIR/cfgms/.claude/agents/reeve.md}"

# The GitHub App. The numbers are not secrets, but they belong to one
# account, so they are host settings and not in this file. The settings file
# is read as data (digits only), never run.
REEVE_CONF="${CFGMS_REEVE_CONF:-$HOME/.config/cfgms/reeve.conf}"
conf_number() {
  [[ -f "$REEVE_CONF" && -r "$REEVE_CONF" ]] || return 0
  sed -n "s/^$1=\([0-9][0-9]*\)[[:space:]]*\$/\1/p" "$REEVE_CONF" | head -n 1
}
APP_ID="${CFGMS_REEVE_APP_ID:-$(conf_number app_id)}"
INSTALLATION_ID="${CFGMS_REEVE_INSTALLATION_ID:-$(conf_number installation_id)}"
APP_KEY_CRED="${CFGMS_REEVE_KEY_CRED:-$HOME/.config/cfgms/reeve-app-key.cred}"

CONTAINER="cfg-reeve"
TMUX_SESSION="cfg-reeve"
IMAGE="cfg-agent:latest"
REFRESH_SECS=2700 # 45 minutes; a token lives 60
API="https://api.github.com"
ACCEPT="Accept: application/vnd.github+json"

# The container program: the same host setting as the pipeline scripts
# (cfgms-tooling scripts/lib/container-runtime.sh). First match wins:
# CFGMS_CONTAINER_RUNTIME, then the first word of
# ~/.config/cfgms/container-runtime, then docker.
RUNTIME="${CFGMS_CONTAINER_RUNTIME:-}"
if [[ -z "$RUNTIME" && -r "${CFGMS_CONTAINER_RUNTIME_FILE:-$HOME/.config/cfgms/container-runtime}" ]]; then
  read -r RUNTIME _ < "${CFGMS_CONTAINER_RUNTIME_FILE:-$HOME/.config/cfgms/container-runtime}" || true
fi
RUNTIME="${RUNTIME:-docker}"
# In rootless podman the host user is root in the container. These options make
# the host user and the image's `agent` user (uid 1000) the same user, and keep
# the container starting as its own root for the firewall setup.
RUNTIME_RUN_ARGS=()
case "$RUNTIME" in
  docker) ;;
  podman) RUNTIME_RUN_ARGS=(--user 0 --userns=keep-id:uid=1000,gid=1000) ;;
  *) echo "ERROR: unknown container runtime '$RUNTIME' (use docker or podman)" >&2; exit 2 ;;
esac

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# The TPM device is readable by group `tss` only. Re-run under that group when
# this shell does not have it yet.
need_tss() {
  if ! id -nG | tr ' ' '\n' | grep -qx tss; then
    exec sg tss -c "$(printf '%q ' "$0" "$@")"
  fi
}

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

make_jwt() {
  local now header payload sig
  now=$(date +%s)
  header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  payload=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' $((now - 60)) $((now + 540)) "$APP_ID" | b64url)
  sig=$(printf '%s.%s' "$header" "$payload" \
    | openssl dgst -sha256 -binary \
        -sign <(timeout 15 systemd-creds decrypt --name=reeve-app-key "$APP_KEY_CRED" -) \
    | b64url)
  [[ -n "$sig" ]] || return 1
  printf '%s.%s.%s' "$header" "$payload" "$sig"
}

request_token() { # $1 jwt, $2 request body -> prints the token
  curl -fsS -X POST -H "Authorization: Bearer $1" -H "$ACCEPT" -d "$2" \
    "$API/app/installations/$INSTALLATION_ID/access_tokens" | jq -er '.token'
}

write_secret() { # $1 file name, $2 value. Replaces the file in one step.
  (umask 077; printf '%s' "$2" > "$TOKEN_DIR/.$1.tmp")
  mv -f "$TOKEN_DIR/.$1.tmp" "$TOKEN_DIR/$1"
}

mint_tokens() {
  local jwt canon cfgms
  jwt=$(make_jwt) || return 1
  canon=$(request_token "$jwt" \
    '{"repositories":["cfgms-canon"],"permissions":{"contents":"write"}}') || return 1
  cfgms=$(request_token "$jwt" \
    '{"repositories":["cfgms"],"permissions":{"issues":"write","organization_projects":"write"}}') || return 1
  write_secret canon.token "$canon"
  write_secret cfgms.token "$cfgms"
}

revoke_tokens() {
  local f code
  for f in "$TOKEN_DIR/canon.token" "$TOKEN_DIR/cfgms.token"; do
    [[ -s "$f" ]] || continue
    code=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE \
      -H "Authorization: Bearer $(cat "$f")" "$API/installation/token" || true)
    log "revoke $(basename "$f"): ${code}"
    rm -f "$f"
  done
  rm -f "$TOKEN_DIR"/.*.tmp 2>/dev/null || true
}

container_running() { # $1 = container name or id (default: the name)
  [[ "$("$RUNTIME" inspect -f '{{.State.Running}}' "${1:-$CONTAINER}" 2>/dev/null)" == "true" ]]
}

# Stop every refresh loop without running its exit trap. The caller owns the
# token files after this.
kill_refresh_loops() {
  pkill -KILL -f "reeve-launch.sh _refresh-loop" 2>/dev/null || true
}

# Runs detached for the life of ONE container. $1 is that container's id, not
# its name: a restart reuses the name, and a loop that watched the name would
# outlive its container and later revoke the new container's tokens.
refresh_loop() {
  local id="$1"
  trap revoke_tokens EXIT
  log "refresh loop started for ${CONTAINER} ${id:0:12}"
  while container_running "$id"; do
    local waited=0
    while (( waited < REFRESH_SECS )); do
      sleep 30
      waited=$((waited + 30))
      container_running "$id" || { log "container stopped"; return 0; }
    done
    until mint_tokens; do
      log "token refresh failed; retry in 60s"
      sleep 60
      container_running "$id" || { log "container stopped"; return 0; }
    done
    log "tokens refreshed"
  done
}

prepare_cfgms_clone() {
  local clone="$STATE_DIR/cfgms" url
  url=$(git -C "$CFGMS_REPO" remote get-url origin)
  if [[ ! -d "$clone/.git" ]]; then
    git clone --quiet --local --no-checkout "$CFGMS_REPO" "$clone"
    git -C "$clone" remote set-url origin "$url"
  fi
  git -C "$clone" fetch --quiet origin develop
  git -C "$clone" checkout --quiet -B develop origin/develop
  git -C "$clone" submodule update --quiet --init .claude/tooling
}

cmd_start() {
  need_tss start "$@"

  # A new session starts with Reeve's read-first list. A continued session
  # keeps its own thread and gets no new prompt.
  local claude_args=("Start of session. Do your read-first list. Then tell the founder, in a few short lines, what waits for them.")
  case "${1:-}" in
    --continue) claude_args=(--continue) ;;
    --resume)
      if [[ -n "${2:-}" ]]; then claude_args=(--resume "$2"); else claude_args=(--continue); fi ;;
    "") ;;
    *) die "unknown option: $1" ;;
  esac

  container_running && die "${CONTAINER} is already running. Use: $0 stop"
  command -v tmux >/dev/null || die "tmux is not installed on the host"
  [[ "$APP_ID" =~ ^[0-9]+$ && "$INSTALLATION_ID" =~ ^[0-9]+$ ]] \
    || die "GitHub App numbers not set: put app_id=<number> and installation_id=<number> in $REEVE_CONF"
  [[ -f "$CONTAINER_SETUP" ]] || die "container setup script not found: $CONTAINER_SETUP"
  [[ -f "$APP_KEY_CRED" ]] || die "app key credential not found: $APP_KEY_CRED"
  [[ -f "$HOME/.claude/.credentials.json" ]] || die "no Claude login on the host: $HOME/.claude/.credentials.json"
  [[ -d "$CC_MEMORY_DIR" ]] || die "Claude Code memory folder not found: $CC_MEMORY_DIR"

  [[ -d "$CANON_DIR/.git" ]] || die "cfgms-canon clone not found: $CANON_DIR"
  [[ -d "$MEMORY_DIR" ]] || die "cfgms-memory folder not found: $MEMORY_DIR"
  # No host git in cfgms-canon (see the header). The container checks that
  # canon is on main and clean, and updates it, before Claude starts.

  # The agent definition is a project-level agent of /workspace, so it does
  # not land in the host's own ~/.claude/agents.
  mkdir -p "$STATE_DIR/workspace/.claude/agents" \
    "$STATE_DIR/workspace/cfgms" "$STATE_DIR/workspace/cfgms-canon" \
    "$STATE_DIR/workspace/cfgms-memory" "$STATE_DIR/workspace/claude-code-memory"
  (umask 077; mkdir -p "$TOKEN_DIR")

  prepare_cfgms_clone
  [[ -f "$REEVE_DEF" ]] || die "reeve definition not found: $REEVE_DEF"
  cp "$REEVE_DEF" "$STATE_DIR/workspace/.claude/agents/reeve.md"

  "$RUNTIME" rm -f "$CONTAINER" >/dev/null 2>&1 || true
  tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
  kill_refresh_loops
  revoke_tokens

  mint_tokens || die "cannot make the Reeve GitHub tokens"

  # Claude login: the same way as po-live. The host's ~/.claude and
  # ~/.claude.json are mounted, so Reeve uses the founder's full login.
  # Remote control needs that; the long-lived container token is refused.
  #
  # Terminal: a detached container has a terminal of size 0 and the screen
  # stays blank. A detached host tmux session gives it a real one, and needs
  # no terminal from the caller.
  # shellcheck disable=SC2016  # $PATH and $@ expand inside the container
  local run=("$RUNTIME" run "${RUNTIME_RUN_ARGS[@]}" -it --rm
    --name "$CONTAINER"
    --label "cfg-agent=true"
    --label "mode=reeve"
    --memory=4g
    --cpus=4
    -v "$STATE_DIR/workspace:/workspace"
    -v "$STATE_DIR/cfgms:/workspace/cfgms:ro"
    -v "$CANON_DIR:/workspace/cfgms-canon"
    -v "$MEMORY_DIR:/workspace/cfgms-memory:ro"
    -v "$CC_MEMORY_DIR:/workspace/claude-code-memory:ro"
    -v "$HOME/.claude:/home/agent/.claude"
    -v "$HOME/.claude.json:/home/agent/.claude.json"
    -v "$TOKEN_DIR:/run/reeve-tokens:ro"
    -v "$CONTAINER_SETUP:/usr/local/bin/reeve-container-setup.sh:ro"
    -w /workspace
    --cap-add NET_ADMIN
    --entrypoint /bin/bash
    "$IMAGE"
    -c 'setup-env.sh && runuser -u agent -- reeve-container-setup.sh && exec runuser -u agent -- env PATH="/home/agent/.local/reeve-bin:$PATH" claude --dangerously-skip-permissions --remote-control reeve --agent reeve "$@"'
    _ "${claude_args[@]}")

  tmux new-session -d -s "$TMUX_SESSION" -x 200 -y 50 "${run[@]}" \
    || { revoke_tokens; die "cannot start the tmux session"; }
  # Keep a dead pane, so that a failed start leaves its error on screen.
  tmux set-option -t "$TMUX_SESSION" remain-on-exit on >/dev/null 2>&1 || true

  local container_id="" tries=0
  while (( tries < 30 )); do
    container_id=$("$RUNTIME" inspect -f '{{.Id}}' "$CONTAINER" 2>/dev/null || true)
    [[ -n "$container_id" ]] && break
    sleep 1
    tries=$((tries + 1))
  done
  if [[ -z "$container_id" ]]; then
    echo "--- screen of the failed start ---" >&2
    tmux capture-pane -p -t "$TMUX_SESSION" >&2 || true
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
    revoke_tokens
    die "the container did not start"
  fi

  setsid "$(realpath "$0")" _refresh-loop "$container_id" >>"$STATE_DIR/refresh.log" 2>&1 </dev/null &

  echo "Reeve is starting."
  echo "  Open:   https://claude.ai/code   (session name: reeve)"
  echo "  Attach: tmux attach -t ${TMUX_SESSION}   (leave with Ctrl-b d)"
  echo "  Screen: $0 screen"
  echo "  Stop:   $0 stop"
}

cmd_stop() {
  "$RUNTIME" stop "$CONTAINER" >/dev/null 2>&1 || true
  "$RUNTIME" rm "$CONTAINER" >/dev/null 2>&1 || true
  tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
  # The refresh loop does the same when it sees its container stop (for
  # example when Reeve exits by itself). Doing it here makes it immediate.
  kill_refresh_loops
  if [[ -d "$TOKEN_DIR" ]]; then revoke_tokens; fi
  echo "Reeve is stopped. Continue the same conversation with: $0 start --continue"
}

cmd_status() {
  if container_running; then echo "container: running"; else echo "container: not running"; fi
  if pgrep -f "reeve-launch.sh _refresh-loop" >/dev/null; then
    echo "refresh loop: running"
  else
    echo "refresh loop: not running"
  fi
  local f
  for f in canon.token cfgms.token; do
    if [[ -s "$TOKEN_DIR/$f" ]]; then
      echo "${f}: present, written $(date -r "$TOKEN_DIR/$f" +%H:%M:%S)"
    else
      echo "${f}: absent"
    fi
  done
}

case "${1:-}" in
  start) shift; cmd_start "$@" ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  screen) tmux capture-pane -p -t "$TMUX_SESSION" ;;
  _refresh-loop)
    [[ -n "${2:-}" ]] || die "_refresh-loop needs a container id"
    need_tss _refresh-loop "$2"
    refresh_loop "$2" ;;
  *) echo "usage: $0 start [--continue | --resume <session-id>] | stop | status | screen" >&2; exit 2 ;;
esac
