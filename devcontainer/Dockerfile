# CFGMS Agent Dispatch Container
# Provides isolated environment for headless Claude Code agent sessions.
# Pre-caches Go modules and Trivy DB to minimize per-agent startup time.
#
# Build: docker build -t cfg-agent:latest -f .devcontainer/Dockerfile .
# Rebuild weekly to refresh Trivy DB: docker build --no-cache -t cfg-agent:latest -f .devcontainer/Dockerfile .

FROM golang:1.25.9-bookworm

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
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# Go-based security and quality tools
# Versions MUST match .github/workflows/dependency-pin-check.yml
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.26.1 \
    && go install honnef.co/go/tools/cmd/staticcheck@2026.1 \
    && go install github.com/zricethezav/gitleaks/v8@v8.30.1 \
    && go install github.com/google/go-licenses/v2@v2.0.1 \
    && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
       | sh -s -- -b "$(go env GOPATH)/bin" v2.12.2

# Trivy — v0.69.4-v0.69.6 are compromised (CVE-2026-33634); v0.70.0 is the
# post-incident clean release. We download the project's release archive and
# verify its SHA-256 against a pinned value before extraction, rather than
# piping the trivy main branch's install.sh through `sh` (whose contents are
# fetched at install time and can be tampered with). See
# docs/runbooks/trivy-rollback.md for rollback procedure.
RUN set -eu; \
    TRIVY_VERSION='v0.70.0'; \
    TRIVY_SHA256='8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9'; \
    ARCHIVE="trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz"; \
    curl -sSfL -o "/tmp/${ARCHIVE}" \
      "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${ARCHIVE}"; \
    printf '%s  /tmp/%s\n' "${TRIVY_SHA256}" "${ARCHIVE}" | sha256sum -c -; \
    tar -xzf "/tmp/${ARCHIVE}" -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f "/tmp/${ARCHIVE}" /tmp/trivy

# Nancy (Go dependency scanner)
RUN GOPATH=$(go env GOPATH) \
    && curl -L "https://github.com/sonatype-nexus-community/nancy/releases/download/v1.2.0/nancy-v1.2.0-linux-amd64" \
       -o "$GOPATH/bin/nancy" \
    && chmod +x "$GOPATH/bin/nancy"

# truffleHog (optional, best-effort secret scanning — pinned version, not @main)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/v3.95.2/scripts/install.sh | sh -s -- -b /usr/local/bin v3.95.2 || true

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

USER agent
WORKDIR /workspace
ENTRYPOINT ["entrypoint.sh"]
