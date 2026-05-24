#!/usr/bin/env bash
# Agent container entrypoint: restore creds, fetch issue, run Claude, update labels.
# Supports three modes: issue (default), branch, and pr-fix.
set -euo pipefail

# Helper library for prompt context assembly (fetch_* / render_* / no-op detection).
# shellcheck source=./agent-context.sh
source "$(dirname "${BASH_SOURCE[0]}")/agent-context.sh"

# Path to the Projects V2 queue helper. The default is the workspace bind-mount
# (every dev container mounts the repo at /workspace, and Dockerfile sets
# WORKDIR /workspace). `dirname "${BASH_SOURCE[0]}")/../scripts/...` would
# resolve to /usr/local/scripts/... — which doesn't exist; entrypoint.sh lives
# at /usr/local/bin/ with no sibling scripts/ dir. Test harness overrides via
# CFGMS_TEST_PROJECT_QUEUE to point at the host repo.
PROJECT_QUEUE="${CFGMS_TEST_PROJECT_QUEUE:-/workspace/scripts/project-queue.sh}"

# --- Argument parsing ---
MODE="issue"
ISSUE_NUM=""
ITEM_ID_SHORT=""
ITEM_MODE="false"
BRANCH=""
PR_NUM=""
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch)  [[ $# -ge 2 ]] || { echo "ERROR: --branch requires a value"; exit 1; }; MODE="branch"; BRANCH="$2"; shift 2 ;;
        --issue)   [[ $# -ge 2 ]] || { echo "ERROR: --issue requires a value"; exit 1; }; ISSUE_NUM="$2"; shift 2 ;;
        --fix-pr)  [[ $# -ge 2 ]] || { echo "ERROR: --fix-pr requires a value"; exit 1; }; MODE="fix-pr"; PR_NUM="$2"; shift 2 ;;
        --dry-run) DRY_RUN="true"; shift ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                ISSUE_NUM="$1"; shift
            elif [[ "$1" =~ ^[a-zA-Z0-9_]+$ ]]; then
                # Non-numeric positional arg: signals item_id mode.
                # ITEM_ID_SHORT is derived from CFGMS_PROJECT_ITEM_ID env var.
                ITEM_MODE="true"; shift
            else
                echo "ERROR: Unknown argument: $1"
                echo "Usage: entrypoint.sh <ISSUE_NUM> [--dry-run]"
                echo "       entrypoint.sh <ITEM_ID> [--dry-run]  (sets item mode)"
                echo "       entrypoint.sh --branch <BRANCH> [--issue <NUM>] [--dry-run]"
                echo "       entrypoint.sh --fix-pr <PR_NUM> [--dry-run]"
                exit 1
            fi
            ;;
    esac
done

# Validate mode-specific requirements
case "$MODE" in
    issue)
        if [[ -z "$ISSUE_NUM" ]]; then
            if [[ "$ITEM_MODE" == "true" && -n "${CFGMS_PROJECT_ITEM_ID:-}" ]]; then
                # Item mode: derive ITEM_ID_SHORT from CFGMS_PROJECT_ITEM_ID
                ITEM_ID_SHORT=$(echo "$CFGMS_PROJECT_ITEM_ID" | tr -cd 'a-zA-Z0-9' | rev | cut -c1-12 | rev)
            else
                echo "ERROR: Issue mode requires an issue number"
                exit 1
            fi
        fi
        ;;
    branch)
        if [[ -z "$BRANCH" ]]; then
            echo "ERROR: Branch mode requires --branch <BRANCH>"
            exit 1
        fi
        ;;
    fix-pr)
        if [[ -z "$PR_NUM" ]]; then
            echo "ERROR: PR-fix mode requires --fix-pr <PR_NUM>"
            exit 1
        fi
        ;;
esac

# --- Phase 0: Environment setup ---

# Shared setup: firewall, credential symlinks, git config (idempotent)
setup-env.sh

# Verify credentials are available (hard fail for headless dispatch)
if [ ! -f ~/.claude/.credentials.json ]; then
    echo "ERROR: No Claude credentials found at /persist/.credentials.json"
    echo "Run: /agent-setup creds on host to configure"
    exit 1
fi

# --- Phase 0b: Validate OAuth token ---
# Check if the access token is expired or expiring soon. If so, a lightweight
# claude call triggers the SDK's built-in token refresh (using the refresh token).
TOKEN_REMAINING=$(python3 -c "
import json, time
d = json.load(open('$HOME/.claude/.credentials.json'))
exp_ms = d.get('claudeAiOauth', {}).get('expiresAt', 0)
print(int((exp_ms / 1000) - time.time()))" 2>/dev/null || echo "0")

if [ "$TOKEN_REMAINING" -lt 300 ] 2>/dev/null; then
    echo "OAuth token expired or expiring in <5min (${TOKEN_REMAINING}s remaining), refreshing..."
    if claude -p 'ping' --dangerously-skip-permissions --model haiku >/dev/null 2>&1; then
        echo "OAuth token refreshed (persisted via symlink)"
    else
        echo "ERROR: OAuth token refresh failed — credentials may be expired"
        echo "Run '/agent-setup creds' on the host to re-authenticate"
        exit 1
    fi
else
    echo "OAuth token valid (${TOKEN_REMAINING}s remaining)"
fi

# --- Helper: GitHub API with retry ---
# Fetches from GitHub API with one retry on failure. Hard-fails if both attempts fail.
# Usage: gh_api_with_retry <description> <command...>
gh_api_with_retry() {
    local desc="$1"
    shift
    local result
    if result=$("$@" 2>&1); then
        echo "$result"
        return 0
    fi
    echo "WARN: ${desc} failed, retrying once..." >&2
    sleep 2
    if result=$("$@" 2>&1); then
        echo "$result"
        return 0
    fi
    echo "ERROR: ${desc} failed after retry: ${result}" >&2
    return 1
}

# --- Shared prompt sections ---
# These are appended to ALL mode prompts for consistent quality standards.

# Self-review checklist — identical across all modes
SELF_REVIEW_SECTION='## Phase 3: Self-Review

Review your own changes for quality issues before proceeding:
- Check for mocks, t.Skip(), empty assertions, hacky workarounds
- Check for hardcoded secrets, SQL injection, information disclosure
- Check for central provider violations (see CLAUDE.md Central Provider System)
- **Log Sanitization Checklist (catches the recurring CodeQL "Log entries created from user input" class):**
  - For every `*.logger.{Debug,Info,Warn,Error}(...)` call you added or touched, identify whether ANY value-side argument comes from the HTTP request.
  - Sources that are tainted: `mux.Vars(r)[...]`, `r.URL.Query().Get(...)`, `r.Header.Get(...)`, `r.FormValue(...)`, `r.URL.Path`, request body fields after `json.NewDecoder(r.Body).Decode(&req)` (i.e. `req.<Field>`), or any local variable assigned from those.
  - Required fix: wrap each tainted value with `logging.SanitizeLogValue(...)`. Example: `s.logger.Info("...", "id", logging.SanitizeLogValue(stewardID))`.
  - Verify by running `make lint-log-injection` — it must exit 0 with no findings.
  - If you intentionally need to log a raw value (rare; almost never correct), document why in a comment on the line above.
- Verify every new .go file has a corresponding _test.go file with functional tests
- Verify tests exercise error paths, not just happy paths
- Fix any issues found'

# Adversarial review phase — the 3-specialist review that catches issues the
# implementing agent is blind to. Uses the same agents as /story-complete.
ADVERSARIAL_REVIEW_SECTION='## Phase 4: Adversarial Team Review (MANDATORY)

Before committing, you MUST spawn three specialist review agents in parallel using
the Agent tool. These agents review your work with fresh context. Read each agent
definition file and include its full instructions in the agent prompt.

**IMPORTANT**: Do NOT skip this phase. Do NOT commit or create a PR before all
three specialists have reported PASS.

### Spawn these three agents in parallel:

1. **qa-test-runner** (subagent_type: qa-test-runner)
   - Read `.claude/agents/qa-test-runner.md` for instructions
   - OVERRIDE: Run `make test-agent-complete` instead of `make test-quality` (no Docker in container)
   - Reports pass/fail with specific test names and error details
   - After it passes, write the marker file: `touch /tmp/agent-validation-passed`

2. **qa-code-reviewer** (subagent_type: qa-code-reviewer)
   - Read `.claude/agents/qa-code-reviewer.md` for instructions
   - Reviews all changed files for test quality, missing tests, mocks, hacky workarounds
   - MUST verify: every new .go file has corresponding _test.go with functional tests
   - MUST reject: new production code without tests, tests without error path coverage

3. **security-engineer** (subagent_type: security-engineer)
   - Read `.claude/agents/security-engineer.md` for instructions
   - Runs security scans and reviews for vulnerabilities, central provider violations
   - Reports blocking issues with file:line references

### After all three report back:

- If ALL three report PASS: proceed to commit phase
- If ANY report BLOCKING issues: fix the issues, then re-run ONLY the failing specialists
- Maximum 3 fix iterations. If issues persist after 3 rounds, commit as draft PR with failure details.'

# Scope constraints — identical across all modes
SCOPE_CONSTRAINTS_SECTION='## Scope Constraints

- Do NOT modify: CLAUDE.md, Makefile root targets, .github/*, docs/product/roadmap.md
- Do NOT add external dependencies without justification
- Do NOT skip tests or create PRs targeting main
- ALWAYS check central providers in pkg/ before creating new functionality'

# Filing follow-up issues — added to every mode prompt so any dev agent that
# needs to file a new issue (audit gap, follow-up work, deferred task, etc.)
# makes it visible to the pipeline. A bare `gh issue create` produces an issue
# with no project item, no status, and no sub-issue link — the dispatcher
# cannot see it. Caught 2026-05-18 on epic #1500: 13 audit stories were filed
# this way and sat orphaned from the pipeline until manual cleanup.
FOLLOW_UP_ISSUES_SECTION='## Filing follow-up issues (when the story tells you to)

If your story asks you to file a follow-up issue (e.g., a docs audit asks you
to file a code-fix issue for each gap found, or a Deferred annotation needs a
tracking issue), DO NOT just call `gh issue create`. A bare `gh issue create`
produces an issue that is invisible to the pipeline — no project item, no
status, no sub-issue link to the parent epic — and the work sits orphaned
until a human cleans it up.

For each follow-up issue, run all FOUR calls in this order. Omit step 2 only
if there is genuinely no parent epic (rare — usually the epic your current
story belongs to is the right parent).

```bash
# 1. Create the public GH issue
issue_num=$(gh issue create --repo cfg-is/cfgms \
  --title "<scope>: <title>" \
  --label story \
  --body-file /path/to/body.md \
  | grep -oE "[0-9]+$")

# 2. Link as sub-issue of the parent epic (so the epic tracks completion)
./scripts/pipeline-helper.sh link-child <PARENT_EPIC_NUM> "$issue_num"

# 3. Add the issue to the project queue (so the dispatcher can see it)
item_id=$(./scripts/project-queue.sh add-issue "$issue_num" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)[\"item_id\"])")

# 4. Set initial status. Use `Draft` if the body needs Tech Lead validation
#    before dispatch (the safe default for new gap-fix work, since you wrote
#    the body without the BA+Tech Lead planning loop). Only use `Ready` if
#    you are certain the body is parser-compliant (`## Dependencies` section
#    is bare `None` or lists only `#NNN` refs to CLOSED issues, and
#    `## Files In Scope` lists concrete file paths).
./scripts/project-queue.sh update-field "$item_id" status "Draft"
```

If any step fails, fix it before moving on — a half-filed issue is worse than
no issue at all because it hides the problem. Story-body conventions the
follow-up issue body must satisfy live in `.claude/agents/po.md` under
"Reference: Story Body Conventions".'

# --- Phase 1: Compose prompt based on mode ---

compose_issue_prompt() {
    echo "Fetching project item ${CFGMS_PROJECT_ITEM_ID}..."
    local item_json
    item_json=$(bash "$PROJECT_QUEUE" get-item "$CFGMS_PROJECT_ITEM_ID") || {
        echo "ERROR: Cannot fetch project item ${CFGMS_PROJECT_ITEM_ID}"
        exit 1
    }

    TITLE=$(echo "$item_json" | jq -r '.title')
    BODY=$(echo "$item_json" | jq -r '.body')

    # Build prompt in a temp file to avoid shell metacharacter corruption.
    # Issue bodies often contain backticks, $ field numbers, etc.
    PROMPT_FILE=$(mktemp)

    if [[ -n "$ISSUE_NUM" ]]; then
        # Issue mode: standard GitHub issue prompt
        printf 'You are implementing GitHub issue #%s: %s\n\n' "$ISSUE_NUM" "$TITLE" > "$PROMPT_FILE"
        printf '%s\n\n' "$BODY" >> "$PROMPT_FILE"
        cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Your branch \`feature/story-${ISSUE_NUM}-agent\` is already checked out from \`develop\`.
Follow the CLAUDE.md file in the repository root — it contains all project conventions,
architecture rules, and coding standards. CFGMS_AGENT_MODE=true is set.

## Phase 1: Implement

1. Read and understand the full issue including acceptance criteria
2. Read CLAUDE.md for project conventions (central providers, storage architecture, etc.)
3. If the issue mentions reference files or patterns, read them first
4. Write tests FIRST for the expected behavior (TDD — tests must fail before implementation)
5. Implement the change to make the tests pass, following existing patterns

## Phase 2: Validate (quick self-check before specialist review)

6. Run \`go test ./path/to/changed/packages/...\` to verify your tests pass locally
7. Fix any compilation or test errors before proceeding to review phase

PROMPT_EOF
        # Append shared sections (contain backticks — must not be inside unquoted heredoc)
        printf '%s\n\n' "$SELF_REVIEW_SECTION" >> "$PROMPT_FILE"
        printf '%s\n\n' "$ADVERSARIAL_REVIEW_SECTION" >> "$PROMPT_FILE"
        cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Phase 5: Commit and PR

After all three specialists report PASS:

8. Run \`go mod tidy\` if dependencies changed
9. Stage all changes with \`git add <specific files>\` (never git add . or git add -A)
10. Commit with message: \`<scope>: <description> (Issue #${ISSUE_NUM})\`
    - Follow commit message format in CLAUDE.md (15-25 lines, WHY + WHAT)
    - Include \`Fixes #${ISSUE_NUM}\` in the commit body
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`
11. Push branch: \`git push -u origin \$(git branch --show-current)\`
12. Open PR targeting \`develop\` (NEVER \`main\`):
    \`gh pr create --base develop --title "<scope>: <title> (Issue #${ISSUE_NUM})"\`
    The PR body MUST include \`Fixes #${ISSUE_NUM}\` on its own line — develop uses squash merge, so the PR body becomes the commit message; without this keyword GitHub will not auto-close the issue on merge.
    Include specialist review results (PASS/FAIL summaries) in the PR body.

## Failure Handling

If specialists report issues that cannot be fixed after 3 iterations:
- Stage all changes and commit with message describing what was attempted
- Push the branch
- Open a DRAFT PR with failure details and specialist reports in the description body
- Exit non-zero

PROMPT_EOF
    else
        # Item mode: project item prompt (no linked GitHub issue to close)
        printf 'You are implementing project item %s: %s\n\n' "$ITEM_ID_SHORT" "$TITLE" > "$PROMPT_FILE"
        printf '%s\n\n' "$BODY" >> "$PROMPT_FILE"
        cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Your branch \`feature/item-${ITEM_ID_SHORT}-agent\` is already checked out from \`develop\`.
Follow the CLAUDE.md file in the repository root — it contains all project conventions,
architecture rules, and coding standards. CFGMS_AGENT_MODE=true is set.

## Phase 1: Implement

1. Read and understand the full item description including acceptance criteria
2. Read CLAUDE.md for project conventions (central providers, storage architecture, etc.)
3. If the item mentions reference files or patterns, read them first
4. Write tests FIRST for the expected behavior (TDD — tests must fail before implementation)
5. Implement the change to make the tests pass, following existing patterns

## Phase 2: Validate (quick self-check before specialist review)

6. Run \`go test ./path/to/changed/packages/...\` to verify your tests pass locally
7. Fix any compilation or test errors before proceeding to review phase

PROMPT_EOF
        printf '%s\n\n' "$SELF_REVIEW_SECTION" >> "$PROMPT_FILE"
        printf '%s\n\n' "$ADVERSARIAL_REVIEW_SECTION" >> "$PROMPT_FILE"
        cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Phase 5: Commit and PR

After all three specialists report PASS:

8. Run \`go mod tidy\` if dependencies changed
9. Stage all changes with \`git add <specific files>\` (never git add . or git add -A)
10. Commit with message: \`<scope>: <description> (Item #${ITEM_ID_SHORT})\`
    - Follow commit message format in CLAUDE.md (15-25 lines, WHY + WHAT)
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`
11. Push branch: \`git push -u origin \$(git branch --show-current)\`
12. Open PR targeting \`develop\` (NEVER \`main\`):
    \`gh pr create --base develop --title "<scope>: <title> (Item #${ITEM_ID_SHORT})"\`
    Include specialist review results (PASS/FAIL summaries) in the PR body.

## Failure Handling

If specialists report issues that cannot be fixed after 3 iterations:
- Stage all changes and commit with message describing what was attempted
- Push the branch
- Open a DRAFT PR with failure details and specialist reports in the description body
- Exit non-zero

PROMPT_EOF
    fi
    printf '%s\n\n' "$SCOPE_CONSTRAINTS_SECTION" >> "$PROMPT_FILE"
    printf '%s\n' "$FOLLOW_UP_ISSUES_SECTION" >> "$PROMPT_FILE"
}

compose_branch_prompt() {
    local issue_context=""

    # Auto-detect issue or item from branch name if not provided
    if [[ -z "$ISSUE_NUM" ]] && [[ "$BRANCH" =~ story-([0-9]+) ]]; then
        ISSUE_NUM="${BASH_REMATCH[1]}"
        echo "Auto-detected issue #${ISSUE_NUM} from branch name"
    elif [[ -z "$ISSUE_NUM" ]] && [[ "$BRANCH" =~ item-([a-zA-Z0-9]+) ]]; then
        ITEM_ID_SHORT="${BASH_REMATCH[1]}"
        echo "Auto-detected item ${ITEM_ID_SHORT} from branch name"
    fi

    # Fetch issue context from Projects V2 — never from gh issue view.
    if [[ -n "$ISSUE_NUM" ]]; then
        echo "Fetching project item ${CFGMS_PROJECT_ITEM_ID} for context..."
        local item_json
        item_json=$(bash "$PROJECT_QUEUE" get-item "$CFGMS_PROJECT_ITEM_ID") || {
            echo "ERROR: Cannot fetch project item ${CFGMS_PROJECT_ITEM_ID}"
            exit 1
        }
        local item_title item_body
        item_title=$(echo "$item_json" | jq -r '.title')
        item_body=$(echo "$item_json" | jq -r '.body')
        issue_context="## Issue Context

GitHub issue #${ISSUE_NUM}: ${item_title}

${item_body}
"
    fi

    # Detect if a PR already exists for this branch
    local pr_instruction="13. Open PR targeting \`develop\` (NEVER \`main\`):
    \`gh pr create --base develop\`
    Include specialist review results (PASS/FAIL summaries) in the PR body."
    EXISTING_PR=$(gh pr list --head "$BRANCH" --json url -q '.[0].url' 2>/dev/null || echo "")
    if [[ -n "$EXISTING_PR" ]]; then
        pr_instruction="13. A PR already exists for this branch (${EXISTING_PR}). Push your changes — do NOT create a new PR."
    fi

    local issue_ref=""
    if [[ -n "$ISSUE_NUM" ]]; then
        issue_ref="
    - Include \`Fixes #${ISSUE_NUM}\` in BOTH the commit body AND the PR body (on its own line). develop uses squash merge, so the PR body becomes the merged commit message; without this keyword GitHub will not auto-close the issue."
    fi

    # Build prompt in a temp file to avoid shell metacharacter corruption.
    PROMPT_FILE=$(mktemp)
    printf 'You are working on existing branch `%s`.\n\n' "$BRANCH" > "$PROMPT_FILE"
    if [[ -n "$issue_context" ]]; then
        printf '%s\n' "$issue_context" >> "$PROMPT_FILE"
    fi
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Branch \`${BRANCH}\` is already checked out. Review existing changes before making
modifications:
- \`git log develop..HEAD\` to see existing commits
- \`git diff develop...HEAD\` to see cumulative changes

Follow the CLAUDE.md file in the repository root — it contains all project conventions,
architecture rules, and coding standards. CFGMS_AGENT_MODE=true is set.

## Phase 1: Implement

1. Review existing work on this branch first
2. Read CLAUDE.md for project conventions (central providers, storage architecture, etc.)
3. Write tests FIRST for new behavior (TDD — tests must fail before implementation)
4. Continue implementation following existing patterns

## Phase 2: Validate (quick self-check before specialist review)

5. Run \`go test ./path/to/changed/packages/...\` to verify your tests pass locally
6. Fix any compilation or test errors before proceeding to review phase

PROMPT_EOF
    # Append shared sections (contain backticks — must not be inside unquoted heredoc)
    printf '%s\n\n' "$SELF_REVIEW_SECTION" >> "$PROMPT_FILE"
    printf '%s\n\n' "$ADVERSARIAL_REVIEW_SECTION" >> "$PROMPT_FILE"
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Phase 5: Commit and Push

After all three specialists report PASS:

7. Run \`go mod tidy\` if dependencies changed
8. Stage all changes with \`git add <specific files>\` (never git add . or git add -A)
9. Commit with message following CLAUDE.md format
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`${issue_ref}
10. Push branch: \`git push -u origin \$(git branch --show-current)\`
${pr_instruction}

## Failure Handling

If specialists report issues that cannot be fixed after 3 iterations:
- Stage all changes and commit with message describing what was attempted
- Push the branch
- If no PR exists, open a DRAFT PR with failure details and specialist reports
- Exit non-zero

PROMPT_EOF
    printf '%s\n\n' "$SCOPE_CONSTRAINTS_SECTION" >> "$PROMPT_FILE"
    printf '%s\n' "$FOLLOW_UP_ISSUES_SECTION" >> "$PROMPT_FILE"
}

compose_pr_fix_prompt() {
    echo "Fetching PR #${PR_NUM} metadata..."
    PR_JSON=$(gh_api_with_retry "fetch PR #${PR_NUM}" ac_fetch_pr_metadata "$PR_NUM") || {
        echo "ERROR: Cannot proceed without PR context"
        exit 1
    }

    local pr_title pr_body pr_branch reviews_json
    pr_title=$(echo "$PR_JSON" | jq -r '.title')
    pr_body=$(echo "$PR_JSON" | jq -r '.body')
    pr_branch=$(echo "$PR_JSON" | jq -r '.headRefName')
    reviews_json=$(echo "$PR_JSON" | jq -c '.reviews // []')
    BRANCH="$pr_branch"

    local owner repo
    owner=$(gh repo view --json owner -q '.owner.login' 2>/dev/null || echo "")
    repo=$(gh repo view --json name -q '.name' 2>/dev/null || echo "")
    if [[ -z "$owner" ]] || [[ -z "$repo" ]]; then
        echo "ERROR: Could not determine repo owner/name — cannot fetch PR comments"
        exit 1
    fi

    echo "Fetching PR inline review comments..."
    local inline_json resolution_json conversation_json failing_checks_json
    inline_json=$(gh_api_with_retry "fetch inline comments for PR #${PR_NUM}" ac_fetch_pr_inline_comments "$owner" "$repo" "$PR_NUM") || {
        echo "ERROR: Cannot proceed without inline review comments"
        exit 1
    }

    echo "Fetching PR conversation comments..."
    conversation_json=$(ac_fetch_pr_conversation_comments "$owner" "$repo" "$PR_NUM" || echo '[]')
    [[ -z "$conversation_json" ]] && conversation_json='[]'

    echo "Fetching review-thread resolution state..."
    resolution_json=$(ac_fetch_review_thread_resolution "$owner" "$repo" "$PR_NUM" || echo '[]')
    [[ -z "$resolution_json" ]] && resolution_json='[]'

    echo "Fetching failing CI check context..."
    failing_checks_json=$(ac_fetch_failing_checks "$PR_NUM" || echo '[]')
    [[ -z "$failing_checks_json" ]] && failing_checks_json='[]'

    # Extract issue number from PR body or branch name
    if [[ -z "$ISSUE_NUM" ]]; then
        ISSUE_NUM=$(echo "$pr_body" | grep -oP 'Fixes #\K[0-9]+' | head -1 || true)
    fi
    if [[ -z "$ISSUE_NUM" ]] && [[ "$pr_branch" =~ story-([0-9]+) ]]; then
        ISSUE_NUM="${BASH_REMATCH[1]}"
    fi

    local issue_ref=""
    local linked_issue_json=""
    if [[ -n "$ISSUE_NUM" ]]; then
        issue_ref=" (Issue #${ISSUE_NUM})"
        echo "Fetching linked issue #${ISSUE_NUM}..."
        linked_issue_json=$(ac_fetch_issue_with_comments "$ISSUE_NUM" || echo "")
    fi

    # Build prompt in a temp file to avoid shell metacharacter corruption.
    # PR bodies and review comments often contain code with backticks and $.
    PROMPT_FILE=$(mktemp)
    printf 'You are fixing PR #%s: %s%s\n\n## PR Description\n\n' "$PR_NUM" "$pr_title" "$issue_ref" > "$PROMPT_FILE"
    printf '%s\n\n' "$pr_body" >> "$PROMPT_FILE"
    printf '## Review Comments to Address\n\n' >> "$PROMPT_FILE"
    ac_render_review_comments "$reviews_json" >> "$PROMPT_FILE"
    printf '\n' >> "$PROMPT_FILE"
    ac_render_inline_comments "$inline_json" "$resolution_json" >> "$PROMPT_FILE"
    printf '\n' >> "$PROMPT_FILE"
    ac_render_conversation_comments "$conversation_json" >> "$PROMPT_FILE"
    printf '\n' >> "$PROMPT_FILE"
    printf '## CI Status\n\n' >> "$PROMPT_FILE"
    ac_render_failing_checks "$failing_checks_json" >> "$PROMPT_FILE"
    printf '\n' >> "$PROMPT_FILE"
    if [[ -n "$linked_issue_json" ]] && echo "$linked_issue_json" | jq -e '.title' >/dev/null 2>&1; then
        ac_render_linked_issue "$linked_issue_json" "$ISSUE_NUM" >> "$PROMPT_FILE"
        printf '\n' >> "$PROMPT_FILE"
    fi
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Branch \`${pr_branch}\` is already checked out. A PR already exists — do NOT create a new one.
Follow the CLAUDE.md file in the repository root. CFGMS_AGENT_MODE=true is set.

## Phase 1: Understand and Fix

1. Read ALL context above in order:
   - Review-Level Comments (formal review submissions)
   - Inline Comments — prioritise \`[UNRESOLVED]\` threads; do NOT re-fix \`[RESOLVED]\` ones unless a newer comment explicitly reopens them
   - PR Conversation Comments (the comment box at the bottom of the PR — this is where human operators most often post fix instructions)
   - Failing CI Checks — if any, treat the log tail as a concrete task: reproduce the failure locally, write a test that exposes it, then fix
   - Linked Issue body + comments — scope clarifications from PO frequently land here
2. Read the code at the mentioned locations
3. For each concern:
   - If it requests new tests: write tests FIRST (TDD), then implement the fix
   - If it identifies a bug or names a failing test: write a test that reproduces it, then fix it
   - If it requests a refactor: ensure existing tests still pass after the change
4. If a comment is unclear, make your best judgment following CLAUDE.md conventions
5. If after careful reading you find nothing actionable: stop, do not commit, and exit 0 — the entrypoint will detect that HEAD did not advance and mark the run as a no-op failure so an operator can investigate

## Phase 2: Validate (quick self-check before specialist review)

5. Run \`go test ./path/to/changed/packages/...\` to verify your fixes compile and pass
6. Fix any compilation or test errors before proceeding to review phase

PROMPT_EOF
    # Append shared sections (contain backticks — must not be inside unquoted heredoc)
    printf '%s\n\n' "$SELF_REVIEW_SECTION" >> "$PROMPT_FILE"
    printf '%s\n\n' "$ADVERSARIAL_REVIEW_SECTION" >> "$PROMPT_FILE"
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Phase 5: Commit and Push

After all three specialists report PASS:

9. Run \`go mod tidy\` if dependencies changed
10. Stage all changes with \`git add <specific files>\` (never git add . or git add -A)
11. Commit with message: \`fix: address PR #${PR_NUM} review comments${issue_ref}\`
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`
    - List which review comments were addressed
12. Push to the existing branch: \`git push\`
13. Do NOT create a new PR — changes will appear on the existing PR #${PR_NUM}

## Failure Handling

If specialists report issues that cannot be fixed after 3 iterations:
- Stage all changes and commit with message describing what was attempted and what failed
- Push to the existing branch
- Exit non-zero

PROMPT_EOF
    printf '%s\n\n' "$SCOPE_CONSTRAINTS_SECTION" >> "$PROMPT_FILE"
    printf '%s\n' "$FOLLOW_UP_ISSUES_SECTION" >> "$PROMPT_FILE"
}

# Hard refusal: issue and branch modes must source content from Projects V2.
# fix-pr reads PR review comments gated by repo write access — a separate surface.
if [[ "$MODE" != "fix-pr" ]] && [[ -z "${CFGMS_PROJECT_ITEM_ID:-}" ]]; then
    echo "ERROR: CFGMS_PROJECT_ITEM_ID must be set — no fallback to gh issue view" >&2
    exit 1
fi

# Compose prompt based on mode
case "$MODE" in
    issue)    compose_issue_prompt ;;
    branch)   compose_branch_prompt ;;
    fix-pr)   compose_pr_fix_prompt ;;
esac

if [ "$DRY_RUN" = "true" ]; then
    echo "=== DRY RUN: Mode=${MODE} ==="
    cat "$PROMPT_FILE"
    rm -f "$PROMPT_FILE"
    exit 0
fi

# --- Phase 2: Run Claude ---

# Project queue status (Ready → In Progress) is managed by po-act.sh dispatch,
# not by the entrypoint — decommissioned with pipeline label substrate (Story #1482).

# Clean validation marker from any previous run
rm -f /tmp/agent-validation-passed

# Capture pre-run HEAD SHA so fix-pr mode can detect silent no-ops.
PRE_FIX_HEAD=$(git rev-parse HEAD 2>/dev/null || echo "")

# All agent modes run on Sonnet 4.6. fix-pr briefly ran on Opus 4.7 (#1580) on
# the hypothesis that stronger reasoning would compress multi-attempt fix loops,
# but multi-round fix loops were already rare (~8% of fix-loop PRs) and the Opus
# token cost was not justified once the pipeline was kept full ahead of the
# cron. agent-result.json now records model + duration so this trade can be
# revisited with real data rather than a hypothesis.
AGENT_MODEL="claude-sonnet-4-6"

echo "Starting Claude agent (mode=${MODE}, model=${AGENT_MODEL})..."
EXIT_CODE=0
# Read prompt from file to avoid shell metacharacter corruption.
# Issue/PR bodies contain backticks and $ in code blocks which break heredoc expansion.
PROMPT_CONTENT=$(cat "$PROMPT_FILE")
AGENT_RUN_START=$(date +%s)
claude --dangerously-skip-permissions --model "$AGENT_MODEL" -p "$PROMPT_CONTENT" || EXIT_CODE=$?
AGENT_DURATION_SECONDS=$(( $(date +%s) - AGENT_RUN_START ))
rm -f "$PROMPT_FILE"

# Credentials persist automatically via symlink to /persist volume — no writeback needed.

# Compute post-run HEAD + advancement state for fix-pr no-op detection + result JSON.
POST_FIX_HEAD=$(git rev-parse HEAD 2>/dev/null || echo "")
HEAD_ADVANCED="false"
if ac_detect_no_op "$PRE_FIX_HEAD" "$POST_FIX_HEAD"; then
    HEAD_ADVANCED="true"
fi

# --- Phase 2b: Silent no-op detection (fix-pr mode) + validation enforcement ---
# In fix-pr mode, a run that exits 0 but never advanced HEAD is a silent no-op.
# The make test-agent-complete fallback would pass trivially on unchanged code,
# masking the failure. Detect the no-op first and skip the fallback entirely.
if [[ "$MODE" == "fix-pr" ]] && [ "$EXIT_CODE" -eq 0 ] && [ "$HEAD_ADVANCED" != "true" ]; then
    echo "ERROR: fix-pr agent ran but made no commits (HEAD unchanged at ${PRE_FIX_HEAD})"
    echo "Skipping make test-agent-complete fallback (would pass trivially on unchanged code)."
    EXIT_CODE=1
    # Best-effort idempotent breadcrumb on the PR.
    _fix_owner=$(gh repo view --json owner -q '.owner.login' 2>/dev/null || echo "")
    _fix_repo=$(gh repo view --json name -q '.name' 2>/dev/null || echo "")
    _container_name="${HOSTNAME:-cfg-agent-pr-fix-${PR_NUM}}"
    if [[ -n "$_fix_owner" ]] && [[ -n "$_fix_repo" ]]; then
        ac_post_no_op_comment "$_fix_owner" "$_fix_repo" "$PR_NUM" "$_container_name" || \
            echo "WARN: failed to post no-op comment on PR #${PR_NUM}"
    fi
elif [ "$EXIT_CODE" -eq 0 ] && [ ! -f /tmp/agent-validation-passed ]; then
    # The agent is instructed to have qa-test-runner write /tmp/agent-validation-passed
    # after make test-agent-complete passes. If the marker is missing, tests either
    # failed or were never run — both are failures.
    echo "ERROR: Agent exited 0 but validation marker not found"
    echo "The qa-test-runner specialist either failed or was not run."
    echo "Running make test-agent-complete as fallback enforcement..."
    if make test-agent-complete; then
        echo "Fallback validation passed — proceeding"
        touch /tmp/agent-validation-passed
    else
        echo "ERROR: make test-agent-complete failed — marking agent as failed"
        EXIT_CODE=1
    fi
fi

# --- Phase 3: Cleanup and reporting ---

# Extract PR URL if one was created
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
PR_URL=$(gh pr list --head "$CURRENT_BRANCH" --json url -q '.[0].url' 2>/dev/null || echo "")

# Update project item with the PR number so the pipeline can track it.
# Non-fatal: a failed set-pr never affects the agent's exit code.
if [[ -n "${CFGMS_PROJECT_ITEM_ID:-}" ]] && [[ -n "$PR_URL" ]] && [[ "$MODE" != "fix-pr" ]]; then
    _pr_num=$(echo "$PR_URL" | grep -oE '[0-9]+$' || true)
    if [[ -n "$_pr_num" ]]; then
        bash "$PROJECT_QUEUE" set-pr "$CFGMS_PROJECT_ITEM_ID" "$_pr_num" \
            || echo "WARN: set-pr failed — continuing"
    fi
fi

# Write result summary
cat > /tmp/agent-result.json <<RESULT_EOF
{
  "mode": "${MODE}",
  "issue": ${ISSUE_NUM:-null},
  "pr_num": ${PR_NUM:-null},
  "exit_code": ${EXIT_CODE},
  "model": "${AGENT_MODEL}",
  "agent_duration_seconds": ${AGENT_DURATION_SECONDS:-null},
  "pr_url": "${PR_URL}",
  "branch": "${CURRENT_BRANCH}",
  "validation_passed": $([ -f /tmp/agent-validation-passed ] && echo "true" || echo "false"),
  "pre_head_sha": "${PRE_FIX_HEAD}",
  "post_head_sha": "${POST_FIX_HEAD}",
  "head_advanced": ${HEAD_ADVANCED},
  "timestamp": "$(date -Iseconds)"
}
RESULT_EOF

# Project queue status (In Progress → Done/Failed) is managed by acceptance-reviewer
# and po-act.sh — decommissioned with pipeline label substrate (Story #1482).

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "Agent completed successfully. PR: ${PR_URL}"

    # If we just finished a fix-pr resume of a session-truncated draft, mark
    # the PR ready for review so the cron's acceptance-reviewer picks it up
    # next cycle. Also rewrite the leftover "WIP: <branch> (agent failed)"
    # title — otherwise it lands on develop verbatim as the squash-merge
    # commit subject. Both calls are idempotent.
    if [[ "$MODE" == "fix-pr" ]] && [[ -n "$PR_URL" ]]; then
        is_draft=$(gh pr view "$PR_URL" --json isDraft -q '.isDraft' 2>/dev/null || echo "false")
        if [[ "$is_draft" == "true" ]]; then
            echo "Resumed PR was a draft; marking ready and cleaning title"
            # Derive a clean title from the linked story issue when possible.
            new_title=""
            if [[ "$CURRENT_BRANCH" =~ feature/story-([0-9]+) ]]; then
                story_num="${BASH_REMATCH[1]}"
                new_title=$(gh issue view "$story_num" --json title -q '.title' 2>/dev/null || echo "")
            fi
            if [[ -n "$new_title" ]]; then
                gh pr edit "$PR_URL" --title "$new_title" 2>/dev/null || true
            fi
            gh pr ready "$PR_URL" 2>/dev/null || true
        fi
    fi
else
    echo "Agent failed with exit code ${EXIT_CODE}"

    if [[ "$MODE" != "fix-pr" ]] && [ -z "$PR_URL" ]; then
        if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
            # Agent produced work but failed — capture it as a draft PR so the
            # cron's resume_failed_session path can pick it up.
            git add --update
            local_issue_ref=""
            if [[ -n "$ISSUE_NUM" ]]; then
                local_issue_ref=" for issue #${ISSUE_NUM}"
            fi
            git commit -m "WIP: agent attempt${local_issue_ref} (failed validation)" \
                2>/dev/null || true
            git push -u origin "$CURRENT_BRANCH" 2>/dev/null || true
            gh pr create --base develop --draft \
                --title "WIP: ${CURRENT_BRANCH} (agent failed)" \
                --body "Agent session failed with exit code ${EXIT_CODE}. Review container logs for details." \
                2>/dev/null || true
        else
            # Zero-work failure: the agent produced no changes — it never got
            # going (usage limit, token reauth, early crash). There is nothing
            # to capture as a draft PR, and leaving the item at In Progress
            # strands it forever (the cron won't re-dispatch In Progress work).
            # Reset it to Ready so the next cron cycle re-dispatches it, capped
            # so a persistent failure escalates instead of looping. The retry
            # count is the number of marker comments on the story issue.
            if [[ -z "${CFGMS_PROJECT_ITEM_ID:-}" ]]; then
                echo "Zero-work failure: no project item id — cannot route for re-dispatch"
            elif [[ -z "$ISSUE_NUM" ]]; then
                # No issue to track retries on — escalate rather than risk an
                # unbounded re-dispatch loop.
                bash "$PROJECT_QUEUE" update-field "$CFGMS_PROJECT_ITEM_ID" status "Blocked" \
                    2>/dev/null || echo "WARN: failed to set status Blocked"
                echo "Zero-work failure (no issue for retry tracking) — set to Blocked"
            else
                zw_marker="<!-- cfgms-zero-work-retry -->"
                zw_count=$(gh issue view "$ISSUE_NUM" --json comments \
                    --jq "[.comments[] | select(.body | contains(\"$zw_marker\"))] | length" \
                    2>/dev/null || echo 0)
                zw_count=${zw_count:-0}
                if [ "$zw_count" -lt 3 ]; then
                    bash "$PROJECT_QUEUE" update-field "$CFGMS_PROJECT_ITEM_ID" status "Ready" \
                        2>/dev/null || echo "WARN: failed to reset status Ready"
                    gh issue comment "$ISSUE_NUM" --body \
                        "${zw_marker} Zero-work agent failure (exit ${EXIT_CODE}) — no changes produced (likely usage limit / token reauth / early crash). Status reset to Ready for re-dispatch (retry $((zw_count + 1))/3)." \
                        2>/dev/null || true
                    echo "Zero-work failure: reset to Ready for re-dispatch (retry $((zw_count + 1))/3)"
                else
                    bash "$PROJECT_QUEUE" update-field "$CFGMS_PROJECT_ITEM_ID" status "Blocked" \
                        2>/dev/null || echo "WARN: failed to set status Blocked"
                    gh issue comment "$ISSUE_NUM" --body \
                        "${zw_marker} Zero-work agent failure (exit ${EXIT_CODE}) — 3 re-dispatch retries exhausted with no progress. Status set to Blocked for operator review." \
                        2>/dev/null || true
                    echo "Zero-work failure: retry cap reached — set to Blocked for operator review"
                fi
            fi
        fi
    fi
fi

exit "$EXIT_CODE"
