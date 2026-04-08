# CFGMS Agent Dispatch Container
# Provides isolated environment for headless Claude Code agent sessions.
# Pre-caches Go modules and Trivy DB to minimize per-agent startup time.
#
# Build: docker build -t cfg-agent:latest -f .devcontainer/Dockerfile .
# Rebuild weekly to refresh Trivy DB: docker build --no-cache -t cfg-agent:latest -f .devcontainer/Dockerfile .

FROM golang:1.25.8-bookworm

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
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.25.0 \
    && go install honnef.co/go/tools/cmd/staticcheck@2026.1 \
    && go install github.com/zricethezav/gitleaks/v8@v8.30.1 \
    && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b "$(go env GOPATH)/bin"

# Trivy (apt repo for stable releases)
RUN curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb bookworm main" \
      > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y trivy=0.69.3 \
    && rm -rf /var/lib/apt/lists/*

# Nancy (Go dependency scanner)
RUN GOPATH=$(go env GOPATH) \
    && curl -L "https://github.com/sonatype-nexus-community/nancy/releases/download/v1.2.0/nancy-v1.2.0-linux-amd64" \
       -o "$GOPATH/bin/nancy" \
    && chmod +x "$GOPATH/bin/nancy"

# truffleHog (optional, best-effort secret scanning — pinned version, not @main)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/v3.94.2/scripts/install.sh | sh -s -- -b /usr/local/bin v3.94.2 || true

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
COPY .devcontainer/dnsmasq-allowlist.conf /etc/dnsmasq-allowlist.conf
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/setup-env.sh /usr/local/bin/entrypoint.sh

# Agent environment — 4GB RAM is sufficient for go test/build + Claude API calls
ENV CFGMS_AGENT_MODE=true
ENV TRIVY_CACHE_DIR=/home/agent/.cache/trivy

USER agent
WORKDIR /workspace
ENTRYPOINT ["entrypoint.sh"]
