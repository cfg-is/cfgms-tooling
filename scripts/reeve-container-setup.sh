#!/usr/bin/env bash
# reeve-container-setup.sh — runs inside the Reeve container, as `agent`,
# after setup-env.sh. Points git and gh at the two narrow tokens that the host
# keeps fresh in /run/reeve-tokens/.
#
# It is not in the agent image: reeve-launch.sh mounts it from the host.
set -euo pipefail

TOKENS=/run/reeve-tokens
BIN="$HOME/.local/reeve-bin"
CANON=/workspace/cfgms-canon

real_gh=$(command -v gh) || { echo "ERROR: gh not found in the image" >&2; exit 1; }
mkdir -p "$BIN"

# gh reads the cfgms token on every call, so a refreshed token is picked up
# without a restart. This token can write issues and the project board only.
cat > "$BIN/gh" <<EOF
#!/bin/sh
GH_TOKEN="\$(cat $TOKENS/cfgms.token)" exec "$real_gh" "\$@"
EOF

# git asks this helper for a password when it talks to cfgms-canon.
cat > "$BIN/git-credential-reeve-canon" <<EOF
#!/bin/sh
[ "\$1" = get ] || exit 0
echo "username=x-access-token"
echo "password=\$(cat $TOKENS/canon.token)"
EOF
chmod 755 "$BIN/gh" "$BIN/git-credential-reeve-canon"

git config --global user.name "cfg-reeve"
git config --global user.email "reeve@cfg.is"

# Only cfgms-canon gets a credential. useHttpPath makes git match the helper
# by the full repo URL, so the canon token is never offered to another repo.
canon_url=$(git -C "$CANON" remote get-url origin)
git config --global --unset-all credential.helper 2>/dev/null || true
git config --global --unset-all "credential.https://github.com.helper" 2>/dev/null || true
git config --global credential.useHttpPath true
git config --global "credential.${canon_url}.helper" "$BIN/git-credential-reeve-canon"

# Canon must be on main, clean and current: Reeve commits straight to main.
# This check is here and not on the host, because the host must not run git
# in a clone whose .git/config a container can write.
[ "$(git -C "$CANON" branch --show-current)" = "main" ] \
  || { echo "ERROR: cfgms-canon is not on main" >&2; exit 1; }
[ -z "$(git -C "$CANON" status --porcelain)" ] \
  || { echo "ERROR: cfgms-canon has uncommitted changes" >&2; exit 1; }
git -C "$CANON" pull --quiet --ff-only \
  || { echo "ERROR: cannot update cfgms-canon from origin" >&2; exit 1; }
