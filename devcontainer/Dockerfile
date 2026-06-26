# CFGMS Agent Dispatch Container
# Provides isolated environment for headless Claude Code agent sessions.
# Pre-caches Go modules and Trivy DB to minimize per-agent startup time.
#
# Build: docker build -t cfg-agent:latest -f .devcontainer/Dockerfile .
# Rebuild weekly to refresh Trivy DB: docker build --no-cache -t cfg-agent:latest -f .devcontainer/Dockerfile .

# Stage 0 (builder): compile cfg binary in an isolated stage so the source tree
# and .git history are never baked into the final image's layers.
# CLI_BINARY=cfg  Entry point: ./cmd/cfg
FROM golang:1.26.4-bookworm AS cfg-builder
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
FROM golang:1.26.4-bookworm

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

# Node.js 22 (required by Claude Code — Debian Bookworm ships Node 18 which
# lacks Array.with() and other APIs used since Claude Code 2.1.79)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
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
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1 \
    && go install honnef.co/go/tools/cmd/staticcheck@2026.1 \
    && go install github.com/zricethezav/gitleaks/v8@v8.30.1 \
    && go install github.com/google/go-licenses/v2@v2.0.1 \
    && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
       | sh -s -- -b "$(go env GOPATH)/bin" v2.12.2

# Trivy — v0.69.4-v0.69.6 are compromised (CVE-2026-33634); v0.71.0 is the
# post-incident clean release. We download the project's release archive and
# verify its SHA-256 against a pinned value before extraction, rather than
# piping the trivy main branch's install.sh through `sh` (whose contents are
# fetched at install time and can be tampered with). See
# docs/runbooks/trivy-rollback.md for rollback procedure.
RUN set -eu; \
    TRIVY_VERSION='v0.71.2'; \
    TRIVY_SHA256='0510e71e2fd39bf863856d499c8dc19feb4e7336546394c502a8f5cc7ab27460'; \
    ARCHIVE="trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz"; \
    curl -sSfL -o "/tmp/${ARCHIVE}" \
      "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${ARCHIVE}"; \
    printf '%s  /tmp/%s\n' "${TRIVY_SHA256}" "${ARCHIVE}" | sha256sum -c -; \
    tar -xzf "/tmp/${ARCHIVE}" -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f "/tmp/${ARCHIVE}" /tmp/trivy

# Nancy (Go dependency scanner)
RUN GOPATH=$(go env GOPATH) \
    && curl -L "https://github.com/sonatype-nexus-community/nancy/releases/download/v2.1.0/nancy-v2.1.0-linux-amd64" \
       -o "$GOPATH/bin/nancy" \
    && chmod +x "$GOPATH/bin/nancy"

# truffleHog (optional, best-effort secret scanning — pinned version, not @main)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/v3.95.6/scripts/install.sh | sh -s -- -b /usr/local/bin v3.95.6 || true

# Claude Code
RUN npm install -g @anthropic-ai/claude-code

# Non-root agent user with sudo for iptables only
RUN useradd -m -s /bin/bash agent \
    && echo "agent ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/dnsmasq, /usr/bin/tee /etc/resolv.conf" > /etc/sudoers.d/agent \
    && mkdir -p /persist && chown agent:agent /persist \
    && mkdir -p /home/agent/.cache/go-build /home/agent/go/pkg/mod \
    && chown -R agent:agent /home/agent/.cache /home/agent/go

# Pre-download Trivy vulnerability DB (avoids runtime download behind firewall)
RUN trivy fs --download-db-only --cache-dir /home/agent/.cache/trivy 2>/dev/null || true
RUN chown -R agent:agent /home/agent/.cache

# Pre-cache Go modules from the project — download as root, then copy to agent
# user's GOPATH so modules are available without the named volume on first run.
WORKDIR /tmp/modcache
COPY go.mod go.sum ./
RUN go mod download \
    && cp -r "$(go env GOPATH)/pkg/mod" /home/agent/go/pkg/mod \
    && chown -R agent:agent /home/agent/go/pkg/mod \
    && rm go.mod go.sum
WORKDIR /

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
RUN set -eu; \
    UV_VERSION='0.11.24'; \
    UV_SHA256='5ce1ad074a78f96c5c8122088bb85a12eb282195bc1453151a48762e4fc31fed'; \
    curl -sSfL -o /tmp/uv.tgz \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz"; \
    printf '%s  /tmp/uv.tgz\n' "${UV_SHA256}" | sha256sum -c -; \
    tar -xzf /tmp/uv.tgz -C /tmp; \
    install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uv  /usr/local/bin/uv; \
    install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uvx /usr/local/bin/uvx; \
    rm -rf /tmp/uv.tgz /tmp/uv-x86_64-unknown-linux-gnu

# gopls — serena's Go language server (pinned), on the shared PATH.
RUN go install golang.org/x/tools/gopls@v0.22.0 \
    && install -m 0755 "$(go env GOPATH)/bin/gopls" /usr/local/bin/gopls

# Install serena (pinned v1.5.3) as a self-contained tool for the agent user.
# This bakes serena + all its Python deps into the image (~/.local/share/uv +
# the `serena` launcher on ~/.local/bin), so at runtime serena starts directly
# from the binary with no uvx git re-resolution and no pypi/astral egress.
# setup-env.sh repoints the project .mcp.json at this binary.
ENV UV_CACHE_DIR=/home/agent/.cache/uv
RUN install -d -o agent -g agent /home/agent/.cache/uv /home/agent/.local \
    && su agent -c 'set -e; export UV_CACHE_DIR=/home/agent/.cache/uv; \
         uv tool install --from git+https://github.com/oraios/serena@v1.5.3 serena-agent' \
    && chown -R agent:agent /home/agent/.cache/uv /home/agent/.local
# Defense-in-depth: keep any stray uv invocation offline behind the firewall.
ENV UV_OFFLINE=1

# Not a long-running service; health checks are not applicable for on-demand
# agent containers. HEALTHCHECK NONE suppresses the Trivy DS-0026 advisory.
HEALTHCHECK NONE

USER agent
WORKDIR /workspace
ENTRYPOINT ["entrypoint.sh"]
