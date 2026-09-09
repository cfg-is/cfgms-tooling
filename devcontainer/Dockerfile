# CFGMS Agent Dispatch Container
# Provides isolated environment for headless Claude Code agent sessions.
# Pre-caches Go modules and Trivy DB to minimize per-agent startup time.
#
# Build: docker build -t cfg-agent:latest -f .devcontainer/Dockerfile .
# Rebuild weekly to refresh Trivy DB: docker build --no-cache -t cfg-agent:latest -f .devcontainer/Dockerfile .

# Stage 0 (builder): compile cfg binary in an isolated stage so the source tree
# and .git history are never baked into the final image's layers.
# CLI_BINARY=cfg  Entry point: ./cmd/cfg
FROM golang:1.27.1-trixie@sha256:9baa6b4187bbb98d240372a8a235ac0bb6b5ddd52bba1431dc2f7c0705862728 AS cfg-builder
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN set -eu; \
    VERSION=$(git describe --tags --always 2>/dev/null || echo "dev"); \
    COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown"); \
    BUILDDATE=$(date -u +%Y-%m-%dT%H:%M:%SZ); \
    GOVERS=$(go version | awk '{print $3}'); \
    go build \
       -ldflags "-X github.com/cfgis/cfgms/pkg/version.Version=${VERSION} -X github.com/cfgis/cfgms/pkg/version.GitCommit=${COMMIT} -X github.com/cfgis/cfgms/pkg/version.BuildDate=${BUILDDATE} -X github.com/cfgis/cfgms/pkg/version.GoVersion=${GOVERS}" \
       -o /usr/local/bin/cfg \
       ./cmd/cfg

# Stage 1 (runtime): main agent container with full tooling
FROM golang:1.27.1-trixie@sha256:9baa6b4187bbb98d240372a8a235ac0bb6b5ddd52bba1431dc2f7c0705862728

# Declare TARGETARCH so BuildKit auto-populates it from the build platform.
# Must be declared inside the consuming stage; an undeclared ${TARGETARCH}
# expands to empty and silently breaks all architecture mappings below.
ARG TARGETARCH

# Run every RUN step in this stage under bash with pipefail, so a failure on the
# LEFT side of a pipe (a curl download feeding `| bash -` / `| sh` / `| gpg`)
# aborts the build instead of being masked by the default /bin/sh (dash has no
# pipefail) — which would silently proceed with an empty/partial download (e.g.
# a 404 on an unpublished Node major would otherwise let apt install Debian's
# stock Node 18). truffleHog below keeps its explicit `|| true` to stay
# best-effort by design.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    jq \
    make \
    sudo \
    iptables \
    ca-certificates \
    gnupg \
    ripgrep \
    dnsutils \
    dnsmasq \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# Node.js — major version tracks web/.nvmrc, the same file frontend-ci.yml reads
# via node-version-file, so the container, CI, and the web toolchain never drift.
# (Debian Bookworm ships Node 18, too old for both the web build and Claude Code,
# which needs >=22 — a web/.nvmrc bump past Claude Code's supported range would
# need checking here since this Node also runs Claude Code.)
COPY web/.nvmrc /tmp/nvmrc
RUN NODE_MAJOR="$(cut -d. -f1 < /tmp/nvmrc)" \
    && curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -f /tmp/nvmrc \
    && rm -rf /var/lib/apt/lists/*

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# Go-based security and quality tools
# Versions MUST match .github/workflows/dependency-pin-check.yml
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0 \
    && go install honnef.co/go/tools/cmd/staticcheck@2026.2.1 \
    && go install github.com/zricethezav/gitleaks/v8@v8.30.1 \
    && go install github.com/google/go-licenses/v2@v2.0.1

# golangci-lint — built from source at the pinned tag with THIS image's Go, not
# downloaded as an upstream release archive.
#
# golangci-lint refuses to start when the Go version it was itself built with is
# older than the version go.mod targets: "the Go language version (goX.Y) used to
# build golangci-lint is lower than the targeted Go version". It reads that target
# from the `toolchain` directive, so every toolchain bump in go.mod breaks a
# prebuilt binary until upstream ships a release rebuilt on the new Go. Issue #3627
# hit exactly that: its bump moved the directive to a Go minor newer than the one
# the prior pinned release archive was built with (go1.26.2), and `make lint`
# failed to load its config with exit 3.
# Building here makes the linter's build Go track the base image's Go, which is the
# same pin the `toolchain` directive carries — the two can no longer drift.
# .github/workflows/golangci-lint.yml installs it the same way (go install under
# GOTOOLCHAIN=${GO_VERSION}), so local and CI runs use one build of one version.
#
# Supply chain: `go install <module>@<tag>` resolves through the Go module proxy and
# is verified against the Go checksum database — the same path the four tools above
# already use. Like the checksum-verified archive it replaces, and unlike the piped
# install.sh that preceded that, nothing unpinned is executed at image-build time;
# it additionally drops the per-architecture SHA-256 values this block had to
# hand-maintain. The version pin below stays the single source of truth and must match
# .github/workflows/dependency-pin-check.yml, .github/workflows/golangci-lint.yml,
# windows-setup.ps1 and the Makefile's GOLANGCI_LINT_VERSION (the `lint` target
# rebuilds the linter itself when the one on PATH predates a toolchain bump).
RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 \
    && golangci-lint --version

# Trivy — v0.69.4-v0.69.6 are compromised (CVE-2026-33634); v0.74.0 is the
# post-incident clean release. We download the project's release archive and
# verify its SHA-256 against a pinned value before extraction, rather than
# piping the trivy main branch's install.sh through `sh` (whose contents are
# fetched at install time and can be tampered with). See
# docs/runbooks/trivy-rollback.md for rollback procedure.
# Per-architecture checksums from trivy_<ver>_checksums.txt release asset at
# https://github.com/aquasecurity/trivy/releases/download/<ver>/trivy_<ver>_checksums.txt
RUN set -eu; \
    TRIVY_VERSION='v0.74.0'; \
    case "$TARGETARCH" in \
      amd64) TRIVY_ARCH='Linux-64bit'; TRIVY_SHA256='2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a' ;; \
      arm64) TRIVY_ARCH='Linux-ARM64'; TRIVY_SHA256='b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5' ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    ARCHIVE="trivy_${TRIVY_VERSION#v}_${TRIVY_ARCH}.tar.gz"; \
    curl -sSfL -o "/tmp/${ARCHIVE}" \
      "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${ARCHIVE}"; \
    printf '%s  /tmp/%s\n' "${TRIVY_SHA256}" "${ARCHIVE}" | sha256sum -c -; \
    tar -xzf "/tmp/${ARCHIVE}" -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f "/tmp/${ARCHIVE}" /tmp/trivy

# Nancy (Go dependency scanner)
RUN set -eu; \
    GOPATH=$(go env GOPATH); \
    case "$TARGETARCH" in \
      amd64) NANCY_ARCH='linux-amd64' ;; \
      arm64) NANCY_ARCH='linux-arm64' ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -L "https://github.com/sonatype-nexus-community/nancy/releases/download/v2.1.0/nancy-v2.1.0-${NANCY_ARCH}" \
       -o "$GOPATH/bin/nancy" \
    && chmod +x "$GOPATH/bin/nancy"

# truffleHog (optional, best-effort secret scanning — pinned version, not @main)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/v3.97.1/scripts/install.sh | sh -s -- -b /usr/local/bin v3.97.1 || true

# Claude Code — pinned, never @latest (same supply-chain rule as every other
# tool here; see dependency-pin-check.yml). An unpinned install also froze
# silently: the RUN layer cache-hits until something above it changes, so the
# image kept shipping whatever version was current when the layer was first
# built while `npm latest` moved on. The pin makes the layer key change with
# the version, and dependency-pin-check.yml files a weekly issue when npm's
# dist-tags.latest moves ahead of it.
ARG CLAUDE_CODE_VERSION=2.1.258
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"

# Codex CLI — pinned, never @latest (same supply-chain rule as Claude Code
# above; see dependency-pin-check.yml). This is the second subscription
# agent harness the security review harness dispatches (Issue #3935,
# epic #3927) — `codex_lane.py` invokes this binary as a subprocess,
# authenticated by the operator's own `~/.codex/auth.json` session
# (`agent-dispatch.sh launch-investigator --harness codex`), never an
# OS-keychain API key.
ARG CODEX_CLI_VERSION=0.153.4
RUN npm install -g "@openai/codex@${CODEX_CLI_VERSION}"

# OpenCode CLI — pinned, never @latest (same supply-chain rule as Claude Code
# and Codex above; see dependency-pin-check.yml). This is the third
# subscription agent harness the security review harness dispatches (Issue
# #3936, epic #3927) — `opencode_lane.py` invokes this binary as a
# subprocess, authenticated by the operator's own
# `~/.local/share/opencode/auth.json` OpenCode Zen account session
# (`agent-dispatch.sh launch-investigator --harness opencode`), never an
# OS-keychain API key. The npm package is `opencode-ai`, confirmed against
# the package actually installed for this story (its own package.json
# declares `"bin": {"opencode": "./bin/opencode.exe"}`).
ARG OPENCODE_CLI_VERSION=1.18.29
RUN npm install -g "opencode-ai@${OPENCODE_CLI_VERSION}"

# Ollama CLI — pinned, never @latest (same supply-chain rule as Claude Code,
# Codex and OpenCode above). This pin is intentionally NOT tracked by
# dependency-pin-check.yml -- that workflow's freshness checks are
# hand-written per tool and adding one is out of scope for the story that
# introduced this pin (Issue #3976). This is the fourth subscription agent
# harness the security review harness dispatches (Issue #3976, epic
# #3975) — `ollama_lane.py` invokes this binary as a subprocess,
# authenticated by the operator's own `~/.ollama/id_ed25519` `ollama
# signin` session keypair (`agent-dispatch.sh launch-investigator --harness
# ollama`), never an API key.
#
# Unlike the three npm-installed harnesses above, there is no client-only
# release asset: the Linux release tarballs (`ollama-linux-<arch>.tar.zst`)
# bundle the CLI/daemon binary (`bin/ollama`, ~38MB) together with a GPU
# runner directory (CUDA/ggml inference libraries, ~4.5GB) in one archive.
# This story is Cloud-only (see the issue's "Out of Scope: Local
# (non-`:cloud`) Ollama models") and needs only the CLI/daemon binary, so
# this step downloads the full archive, verifies its SHA-256 against a
# pinned value (the checksum source is `sha256sum.txt`, the direct analogue
# of Trivy's `trivy_<ver>_checksums.txt` above), and extracts ONLY
# `bin/ollama` — the GPU runner directory is never extracted, never
# copied, never referenced. Everything happens in one RUN so the ~1.4GB
# archive never becomes its own image layer; the final image gains only the
# ~38MB client binary.
#
# Per-architecture checksums from the `sha256sum.txt` release asset at
# https://github.com/ollama/ollama/releases/download/v<ver>/sha256sum.txt
ARG OLLAMA_CLI_VERSION=0.33.3
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) OLLAMA_ARCH='amd64'; OLLAMA_SHA256='c13cea8f3389db4145f8a6cb88d1747242a48639d7c13e3bda7c1ebdc6eebb2f' ;; \
      arm64) OLLAMA_ARCH='arm64'; OLLAMA_SHA256='4425a112af999ae6572c1ce211fbabeaca7bab23ed5860972acdfc0cc2358420' ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    ARCHIVE="ollama-linux-${OLLAMA_ARCH}.tar.zst"; \
    curl -sSfL -o "/tmp/${ARCHIVE}" \
      "https://github.com/ollama/ollama/releases/download/v${OLLAMA_CLI_VERSION}/${ARCHIVE}"; \
    printf '%s  /tmp/%s\n' "${OLLAMA_SHA256}" "${ARCHIVE}" | sha256sum -c -; \
    zstd -dc "/tmp/${ARCHIVE}" | tar -xf - -C /tmp bin/ollama; \
    install -m 0755 /tmp/bin/ollama /usr/local/bin/ollama; \
    rm -rf "/tmp/${ARCHIVE}" /tmp/bin

# Non-root agent user with sudo for iptables only
RUN useradd -m -s /bin/bash agent \
    && echo "agent ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/dnsmasq, /usr/bin/tee /etc/resolv.conf" > /etc/sudoers.d/agent \
    && mkdir -p /persist && chown agent:agent /persist \
    && mkdir -p /home/agent/.cache/go-build /home/agent/go/pkg/mod \
    && chown -R agent:agent /home/agent/.cache /home/agent/go \
    && mkdir -p /home/agent/.claude && chown agent:agent /home/agent/.claude \
    && mkdir -p /home/agent/.ollama && chown agent:agent /home/agent/.ollama

# Pre-download Trivy vulnerability DB (avoids runtime download behind firewall)
RUN trivy fs --download-db-only --cache-dir /home/agent/.cache/trivy 2>/dev/null || true
RUN chown -R agent:agent /home/agent/.cache

# Pre-cache Go modules from the project — download as root, then copy to agent
# user's GOPATH so modules are available without the named volume on first run.
#
# `cp -rT` (not plain `cp -r`): the destination is created empty above, so a
# bare `cp -r SRC DEST` copies SRC *into* DEST and the whole cache lands one
# level too deep at /home/agent/go/pkg/mod/mod/ — invisible to the runtime
# GOMODCACHE set below, so every dispatched agent silently re-downloaded all
# modules from the network. -T treats DEST as the target itself.
#
# The GOPROXY=off re-download is the regression gate: it resolves the module
# graph as the runtime user, at the runtime GOMODCACHE, with the network
# refused. A misplaced or unreadable cache fails the build here instead of
# degrading every dispatch.
WORKDIR /tmp/modcache
COPY go.mod go.sum ./
RUN go mod download \
    && cp -rT "$(go env GOPATH)/pkg/mod" /home/agent/go/pkg/mod \
    && chown -R agent:agent /home/agent/go/pkg/mod \
    && test ! -d /home/agent/go/pkg/mod/mod \
    && su agent -c 'cd /tmp/modcache \
         && GOMODCACHE=/home/agent/go/pkg/mod GOFLAGS=-modcacherw GOPROXY=off \
            go mod download' \
    && rm go.mod go.sum
WORKDIR /

# Pre-warm the npm cache so per-agent `npm ci` in web/ resolves tarballs from the
# warm cache instead of a cold registry pull each dispatch — same rationale as the
# Go module / Trivy DB pre-caches above. We keep the CACHE (~/.npm), not
# node_modules: /workspace is bind-mounted at runtime and the checked-out lockfile
# may differ, so `npm ci` must re-resolve — but it pulls unchanged tarballs from
# the integrity-hash-keyed cache offline and only fetches genuinely-new deps from
# the registry (npmjs.org is allowlisted in dnsmasq-allowlist.conf).
COPY web/package.json web/package-lock.json /tmp/webcache/
RUN chown -R agent:agent /tmp/webcache \
    && su agent -c 'cd /tmp/webcache && npm ci --no-audit --no-fund' \
    && rm -rf /tmp/webcache

# CLI_BINARY=cfg — install cfg CLI built in the builder stage above.
# The builder stage is discarded; only the binary is copied to this layer.
COPY --from=cfg-builder /usr/local/bin/cfg /usr/local/bin/cfg

# Copy container scripts and DNS allowlist. The allowlist is split into a
# base file (everything that is not a model provider) plus per-harness
# fragments under dnsmasq-allowlist.d/ -- init-firewall.sh loads the base
# plus exactly one fragment, selected by the launcher-supplied harness
# (Issue #3932, epic #3927's per-harness egress isolation). This closes the
# one real cross-harness bleed in the single-investigator-image model: every
# container previously resolved every provider's domain regardless of which
# one it authenticated to.
COPY .devcontainer/init-firewall.sh /usr/local/bin/init-firewall.sh
COPY .devcontainer/scripts/setup-env.sh /usr/local/bin/setup-env.sh
COPY .devcontainer/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY .devcontainer/agent-context.sh /usr/local/bin/agent-context.sh
COPY .devcontainer/dnsmasq-allowlist-base.conf /etc/dnsmasq-allowlist-base.conf
COPY .devcontainer/dnsmasq-allowlist.d/ /etc/dnsmasq-allowlist.d/
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/setup-env.sh /usr/local/bin/entrypoint.sh

# Token reporter (Issue #3028/#3041) — baked into the harness so accounting is a
# property of the image, never of the branch under dispatch/review. A PR branch
# that predates this reporter (or edits/deletes it) must not disable its own
# telemetry. The review dispatch path additionally bind-mounts .claude/metrics
# fresh from the host at runtime (see agent-dispatch.sh review-pr), the same
# no-rebuild-required pattern already used for review-entrypoint.sh; this bake
# covers the entrypoint.sh dev/fix/branch paths, which only pick up script
# changes on image rebuild anyway.
COPY .claude/metrics/token_report.py .claude/metrics/pricing.json /usr/local/share/cfgms-metrics/

# Per-segment model routing (Issue #3030) — same rule as the reporter above:
# baked into the harness so the model an agent runs on is a property of the
# image, never of the branch under dispatch/review. Reading this from
# /workspace would let a PR branch select the model of the acceptance reviewer
# deciding whether that branch merges (self-weakening of a merge gate), and dev
# and fix agents consume untrusted issue/PR text. The dispatch paths additionally
# bind-mount the harness checkout's copy over this path at runtime
# (agent-dispatch.sh) so routing edits need no image rebuild.
COPY .claude/model-routing.yaml /usr/local/share/cfgms-agent/model-routing.yaml

# Agent environment — 4GB RAM is sufficient for go test/build + Claude API calls
ENV CFGMS_AGENT_MODE=true
ENV TRIVY_CACHE_DIR=/home/agent/.cache/trivy
ENV GOMODCACHE=/home/agent/go/pkg/mod
ENV GOFLAGS=-modcacherw

# === Serena MCP server (semantic code navigation for PO/dev sessions) ===
# Everything is fetched at BUILD time (unrestricted network) and baked into the
# image. At RUNTIME serena resolves entirely from the warmed uv cache with
# UV_OFFLINE=1, so NO pypi/astral egress is added to the container firewall.
#
# uv/uvx — pinned release binary + SHA-256 (same supply-chain pattern as trivy).
# Per-architecture checksums from <artifact>.tar.gz.sha256 release asset at
# https://github.com/astral-sh/uv/releases/download/<ver>/<artifact>.tar.gz.sha256
# The tarball extracts to a directory named after the artifact triple, so the
# install paths use the resolved triple variable.
RUN set -eu; \
    UV_VERSION='0.11.24'; \
    case "$TARGETARCH" in \
      amd64) UV_TRIPLE='x86_64-unknown-linux-gnu';  UV_SHA256='5ce1ad074a78f96c5c8122088bb85a12eb282195bc1453151a48762e4fc31fed' ;; \
      arm64) UV_TRIPLE='aarch64-unknown-linux-gnu'; UV_SHA256='e22c66d36a0098b17cff80a8647e0b8c58202af899d4e9eb820fc7ad126435a1' ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    ARTIFACT="uv-${UV_TRIPLE}.tar.gz"; \
    curl -sSfL -o /tmp/uv.tgz \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${ARTIFACT}"; \
    printf '%s  /tmp/uv.tgz\n' "${UV_SHA256}" | sha256sum -c -; \
    tar -xzf /tmp/uv.tgz -C /tmp; \
    install -m 0755 "/tmp/uv-${UV_TRIPLE}/uv"  /usr/local/bin/uv; \
    install -m 0755 "/tmp/uv-${UV_TRIPLE}/uvx" /usr/local/bin/uvx; \
    rm -rf /tmp/uv.tgz "/tmp/uv-${UV_TRIPLE}"

# gopls — serena's Go language server (pinned), on the shared PATH.
RUN go install golang.org/x/tools/gopls@v0.22.0 \
    && install -m 0755 "$(go env GOPATH)/bin/gopls" /usr/local/bin/gopls

# Install serena (pinned v1.6.1) as a self-contained tool for the agent user.
# This bakes serena + all its Python deps into the image (~/.local/share/uv +
# the `serena` launcher on ~/.local/bin), so at runtime serena starts directly
# from the binary with no uvx git re-resolution and no pypi/astral egress.
# setup-env.sh repoints the project .mcp.json at this binary.
ENV UV_CACHE_DIR=/home/agent/.cache/uv
RUN install -d -o agent -g agent /home/agent/.cache/uv /home/agent/.local \
    && su agent -c 'set -e; export UV_CACHE_DIR=/home/agent/.cache/uv; \
         uv tool install --from git+https://github.com/oraios/serena@v1.7.0 serena-agent' \
    && chown -R agent:agent /home/agent/.cache/uv /home/agent/.local
# Defense-in-depth: keep any stray uv invocation offline behind the firewall.
ENV UV_OFFLINE=1

# === Security-review scanner toolchain (Issue #3982, epic #3975) ===
# Image-OWNED tools, configs and rules the finder lanes run over an UNTRUSTED
# snapshot mounted read-only at /workspace, next to a live subscription
# credential. Nothing under /workspace is ever loaded as code: eslint runs
# with `--no-config-lookup --config /opt/cfgms-scanner/eslint.config.js`
# against these node_modules (never the audited project's), semgrep reads
# only the rule files installed here, and every argv is a constant from
# .claude/scripts/security-review/lanes/scan_profiles.py. rg, gosec and
# staticcheck are already installed above and are NOT reinstalled.
#
# All three pins below are intentionally NOT tracked by
# dependency-pin-check.yml (same status as the Ollama CLI pin above): its
# freshness checks are hand-written per tool and adding them is outside
# this story. Refresh: bump the versions in .devcontainer/scanner/, regenerate
# the lockfile / hashed requirements as their headers describe, rebuild.
#
# ESLint + plugins: exact versions from .devcontainer/scanner/package.json,
# integrity-pinned by its package-lock.json (`npm ci` refuses a mismatch);
# `--ignore-scripts` so no dependency lifecycle script runs at build.
COPY .devcontainer/scanner/package.json .devcontainer/scanner/package-lock.json /opt/cfgms-scanner/
WORKDIR /opt/cfgms-scanner
RUN npm ci --ignore-scripts --no-audit --no-fund \
    && test -f /opt/cfgms-scanner/node_modules/eslint/bin/eslint.js
WORKDIR /
COPY .devcontainer/scanner/eslint.config.js /opt/cfgms-scanner/eslint.config.js

# semgrep: hash-pinned wheel closure (.devcontainer/scanner/semgrep-requirements.txt,
# `--require-hashes` rejects any artifact whose sha256 is not listed) into a
# private virtualenv on the system Python. Network is needed only here, at
# build time; the runner sets SEMGREP_SEND_METRICS=off and every profile
# passes --metrics=off --disable-version-check, so nothing phones home later.
ARG SEMGREP_VERSION=1.176.1
COPY .devcontainer/scanner/semgrep-requirements.txt /opt/cfgms-scanner/semgrep-requirements.txt
RUN grep -q "^semgrep==${SEMGREP_VERSION} " /opt/cfgms-scanner/semgrep-requirements.txt \
    && UV_OFFLINE=0 uv venv --python /usr/bin/python3 /opt/cfgms-scanner/venv \
    && UV_OFFLINE=0 uv pip install --python /opt/cfgms-scanner/venv/bin/python \
         --require-hashes --no-cache -r /opt/cfgms-scanner/semgrep-requirements.txt \
    && /opt/cfgms-scanner/venv/bin/semgrep --version

# semgrep rules: the curated upstream Go + TS/React security rules are fetched
# at the commit pinned in semgrep/upstream/SOURCE and verified file-by-file
# against the sha256 recorded there (fetch-semgrep-rules.sh fails the build on
# any mismatch); the CFGMS project rules are copied from the repository.
COPY .devcontainer/scanner/semgrep/upstream/SOURCE /tmp/semgrep-upstream-SOURCE
COPY .devcontainer/scanner/fetch-semgrep-rules.sh /usr/local/bin/fetch-semgrep-rules.sh
RUN chmod 0755 /usr/local/bin/fetch-semgrep-rules.sh \
    && /usr/local/bin/fetch-semgrep-rules.sh /tmp/semgrep-upstream-SOURCE /opt/cfgms-scanner/semgrep/upstream \
    && rm -f /tmp/semgrep-upstream-SOURCE
COPY .devcontainer/scanner/semgrep/cfgms/ /opt/cfgms-scanner/semgrep/cfgms/
# Validate every rule file parses at build time, offline, so a broken rule
# fails the build rather than silently producing an empty scan later.
RUN SEMGREP_SEND_METRICS=off /opt/cfgms-scanner/venv/bin/semgrep --validate --metrics=off --disable-version-check \
      --config /opt/cfgms-scanner/semgrep/upstream/go \
      --config /opt/cfgms-scanner/semgrep/upstream/typescript \
      --config /opt/cfgms-scanner/semgrep/cfgms/go \
      --config /opt/cfgms-scanner/semgrep/cfgms/typescript
# Read-only for the agent user; the runner never writes here.
RUN chmod -R a+rX /opt/cfgms-scanner

# Not a long-running service; health checks are not applicable for on-demand
# agent containers. HEALTHCHECK NONE suppresses the Trivy DS-0026 advisory.
HEALTHCHECK NONE

USER agent
WORKDIR /workspace
ENTRYPOINT ["entrypoint.sh"]
