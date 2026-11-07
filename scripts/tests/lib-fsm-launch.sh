#!/usr/bin/env bash
# Shared stand-ins for shell tests of po-act.sh's FSM launch path (sourced).
#
#   fsm_launch_fakes <dir>
#     Creates under <dir>:
#       img-repo/        a git repo with .claude/tooling/devcontainer, exported
#                        as CFGMS_TEST_REPO_ROOT; FAKE_IMAGE_LABEL is set to its
#                        build-inputs hash, so the image gate passes unless a
#                        test changes FAKE_IMAGE_LABEL
#       bin/docker       answers the image-label inspect, logs every call to
#                        <dir>/docker.log, fails `run` / `build` / `tag` loudly
#       supervisor.py    stands in for scripts/fsm/supervisor.py
#                        (CFGMS_TEST_FSM_SUPERVISOR); logs its argv to
#                        <dir>/supervisor.log and writes a run dir the real
#                        runindex.py reads. FAKE_SUP_MODE picks the outcome:
#                          launched (default)  gates_ok + agent_launched
#                          agentless           gates_ok -> SYNC, no agent
#                          refused:<reason>    REFUSED, FSM_REFUSED line, exit 3
#                          deferred:<reason>   REFUSED, DISPATCH_DEFERRED line, exit 0
#                          failed              FAILED before any agent, exit 1
#                          exit:<n>            no records, exit n
#       project-queue.sh answers get-item / list-by-status / item-for-issue /
#                        update-field for one story (FAKE_PQ_STORY,
#                        FAKE_PQ_ITEM, FAKE_PQ_BODY), status kept in a file
#     and exports CFGMS_FSM_RUNS_DIR=<dir>/runs, CFGMS_FSM_LAUNCH_POLL_SECS.
#     The caller prepends <dir>/bin to PATH.

fsm_launch_fakes() {
  local d="$1" tooling
  tooling="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  mkdir -p "$d/bin" "$d/runs" "$d/img-repo/.claude/tooling/devcontainer"
  echo "FROM scratch" > "$d/img-repo/.claude/tooling/devcontainer/Dockerfile"
  git -c init.defaultBranch=main -C "$d/img-repo" init -q
  git -C "$d/img-repo" add .claude
  git -c user.email=t@t -c user.name=t -C "$d/img-repo" commit -q -m img
  export CFGMS_TEST_REPO_ROOT="$d/img-repo"
  FAKE_IMAGE_LABEL="$(git -C "$d/img-repo" rev-parse HEAD:.claude/tooling/devcontainer)"
  export FAKE_IMAGE_LABEL
  export FSM_LAUNCH_FAKES_DIR="$d"
  export CFGMS_FSM_RUNS_DIR="$d/runs"
  export CFGMS_FSM_LAUNCH_POLL_SECS=0.2
  export CFGMS_TEST_FSM_SUPERVISOR="$d/supervisor.py"
  export CFGMS_TEST_PROJECT_QUEUE="$d/project-queue.sh"
  export FAKE_SUP_FSM_DIR="${tooling}/scripts/fsm"

  cat > "$d/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FSM_LAUNCH_FAKES_DIR}/docker.log"
case "$1" in
  inspect) [[ "$*" == *cfgms.build_inputs_hash* ]] && printf '%s\n' "${FAKE_IMAGE_LABEL:-}"; exit 0 ;;
  run|build|tag) echo "FAKE_DOCKER_UNEXPECTED:$1" >&2; exit 99 ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "$d/bin/docker"

  cat > "$d/supervisor.py" <<'EOF'
import os, sys
sys.path.insert(0, os.environ["FAKE_SUP_FSM_DIR"])
import state
argv = sys.argv[1:]
with open(os.path.join(os.environ["FSM_LAUNCH_FAKES_DIR"], "supervisor.log"), "a") as fh:
    fh.write(" ".join(argv) + "\n")
mode = os.environ.get("FAKE_SUP_MODE", "launched")
if mode.startswith("exit:"):
    sys.exit(int(mode[5:]))
run_mode, target = argv[1], argv[2]
key = argv[argv.index("--lease-key") + 1]
rid = "%s-fake-%d" % (key.replace("_", "-")[:60], os.getpid())
r = state.RunDir(rid)
r.create({"mode": run_mode, "target": target, "key": key, "lease_key": key,
          "item_id": argv[argv.index("--item-id") + 1] if "--item-id" in argv else None})
print("FSM_RUN:" + rid, flush=True)
container = {"fix-pr": "cfg-agent-pr-fix-", "resolve-conflict": "cfg-agent-resolve-conflict-"}.get(
    run_mode, "cfg-agent-") + target
t = lambda frm, ev, to, reason="": r.append("transition", frm=frm, event=ev, to=to, kind="", reason=reason)
if mode == "launched":
    t("PREPARE", "gates_ok", "AGENT")
    r.append("agent_launched", container=container, kind="implement", seq=1)
elif mode == "agentless":
    t("PREPARE", "gates_ok", "SYNC")
elif mode.startswith(("refused:", "deferred:")):
    reason = mode.split(":", 1)[1]
    t("PREPARE", "gate_refused", "REFUSED", reason)
    r.append("terminal_done", state="REFUSED")
    token = "DISPATCH_DEFERRED" if mode.startswith("deferred:") else "FSM_REFUSED"
    print(f"{token}:{target}:{reason}", flush=True)
    sys.exit(0 if token == "DISPATCH_DEFERRED" else 3)
elif mode == "failed":
    t("PREPARE", "error", "FAILED", "prepare_error")
    r.append("terminal_done", state="FAILED")
    sys.exit(1)
EOF

  cat > "$d/project-queue.sh" <<'EOF'
#!/usr/bin/env bash
printf 'project-queue %s\n' "$*" >> "${FSM_LAUNCH_FAKES_DIR}/pq.log"
story="${FAKE_PQ_STORY:-4242}"; item="${FAKE_PQ_ITEM:-PVTI_fakeitem}"
sf="${FSM_LAUNCH_FAKES_DIR}/board-status"
status="$(cat "$sf" 2>/dev/null || echo Ready)"
item_json() {
  FAKE_ITEM="$item" FAKE_STORY="$story" FAKE_STATUS="$status" python3 -c '
import json, os
print(json.dumps({"item_id": os.environ["FAKE_ITEM"], "issue_num": int(os.environ["FAKE_STORY"]),
                  "status": os.environ["FAKE_STATUS"], "title": "t",
                  "body": os.environ.get("FAKE_PQ_BODY", ""), "fields": {}}))'
}
case "$1" in
  get-item) item_json ;;
  list-by-status) if [[ "$2" == "$status" ]]; then printf '[%s]\n' "$(item_json)"; else echo '[]'; fi ;;
  item-for-issue) [[ "$2" == "$story" ]] && { echo "$item"; exit 0; }; exit 3 ;;
  update-field) [[ "$3" == "status" ]] && printf '%s\n' "$4" > "$sf"; echo OK ;;
  *) echo OK ;;
esac
EOF
  chmod +x "$d/project-queue.sh"
}
