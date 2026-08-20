# CFGMS Agent Dispatch Container
# Provides isolated environment for headless Claude Code agent sessions.
# Pre-caches Go modules and Trivy DB to minimize per-agent startup time.
#
# Build: docker build -t cfg-agent:latest -f .devcontainer/Dockerfile .
# Rebuild weekly to refresh Trivy DB: docker build --no-cache -t cfg-agent:latest -f .devcontainer/Dockerfile .

# Stage 0 (builder): compile cfg binary in an isolated stage so the source tree
# and .git history are never baked into the final image's layers.
# CLI_BINARY=cfg  Entry point: ./cmd/cfg
FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS cfg-builder
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
FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36

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
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.28.0 \
    && go install honnef.co/go/tools/cmd/staticcheck@2026.1 \
    && go install github.com/zricethezav/gitleaks/v8@v8.30.1 \
    && go install github.com/google/go-licenses/v2@v2.0.1

# golangci-lint — same rule as Trivy below: download the pinned release archive
# and verify its SHA-256 before extraction, rather than piping the project's
# install.sh through `sh`. The previous form fetched that script from the
# golangci-lint repo's HEAD, so its contents were whatever the branch tip held
# at image-build time — an unpinned remote script executing as root, which is
# the exact pattern the Trivy block was rewritten to avoid.
# Per-architecture checksums from the golangci-lint-<ver>-checksums.txt release
# asset at https://github.com/golangci/golangci-lint/releases/download/v<ver>/
RUN set -eu; \
    GOLANGCI_VERSION='2.12.2'; \
    case "$TARGETARCH" in \
      amd64) GOLANGCI_ARCH='linux-amd64'; GOLANGCI_SHA256='8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553' ;; \
      arm64) GOLANGCI_ARCH='linux-arm64'; GOLANGCI_SHA256='44cd40a8c76c86755375adfeea52cfd3533cb43d7bd647771e0ae065e166df3a' ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    STEM="golangci-lint-${GOLANGCI_VERSION}-${GOLANGCI_ARCH}"; \
    curl -sSfL -o "/tmp/${STEM}.tar.gz" \
      "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_VERSION}/${STEM}.tar.gz"; \
    printf '%s  /tmp/%s.tar.gz\n' "${GOLANGCI_SHA256}" "${STEM}" | sha256sum -c -; \
    tar -xzf "/tmp/${STEM}.tar.gz" -C /tmp "${STEM}/golangci-lint"; \
    install -m 0755 "/tmp/${STEM}/golangci-lint" "$(go env GOPATH)/bin/golangci-lint"; \
    rm -rf "/tmp/${STEM}.tar.gz" "/tmp/${STEM}"

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
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/v3.97.0/scripts/install.sh | sh -s -- -b /usr/local/bin v3.97.0 || true

# Claude Code — pinned, never @latest (same supply-chain rule as every other
# tool here; see dependency-pin-check.yml). An unpinned install also froze
# silently: the RUN layer cache-hits until something above it changes, so the
# image kept shipping whatever version was current when the layer was first
# built while `npm latest` moved on. The pin makes the layer key change with
# the version, and dependency-pin-check.yml files a weekly issue when npm's
# dist-tags.latest moves ahead of it.
ARG CLAUDE_CODE_VERSION=2.1.232
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"

# Non-root agent user with sudo for iptables only
RUN useradd -m -s /bin/bash agent \
    && echo "agent ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/dnsmasq, /usr/bin/tee /etc/resolv.conf" > /etc/sudoers.d/agent \
    && mkdir -p /persist && chown agent:agent /persist \
    && mkdir -p /home/agent/.cache/go-build /home/agent/go/pkg/mod \
    && chown -R agent:agent /home/agent/.cache /home/agent/go \
    && mkdir -p /home/agent/.claude && chown agent:agent /home/agent/.claude

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

# Copy container scripts and DNS allowlist
COPY .devcontainer/init-firewall.sh /usr/local/bin/init-firewall.sh
COPY .devcontainer/scripts/setup-env.sh /usr/local/bin/setup-env.sh
COPY .devcontainer/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY .devcontainer/agent-context.sh /usr/local/bin/agent-context.sh
COPY .devcontainer/dnsmasq-allowlist.conf /etc/dnsmasq-allowlist.conf
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

# Not a long-running service; health checks are not applicable for on-demand
# agent containers. HEALTHCHECK NONE suppresses the Trivy DS-0026 advisory.
HEALTHCHECK NONE

USER agent
WORKDIR /workspace
ENTRYPOINT ["entrypoint.sh"]
