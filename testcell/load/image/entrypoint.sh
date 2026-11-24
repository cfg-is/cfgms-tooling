#!/bin/sh
# Virtual steward entrypoint (cfg-is/cfgms#5981). Prepares the per-steward state and
# then execs the launcher, which stays PID 1 for the container's life and supervises
# the steward (a steward not started by the launcher stages upgrades but never
# applies them).
#
# Inputs, all supplied by the harness:
#   VSTEWARD_CONTROLLER_URL   controller REST URL used for first registration
#   /run/secrets/regtoken     registration token (podman/docker secret)
#   /run/vsteward/controller-ca.crt   controller CA certificate (read-only mount)
# Persistent volumes: /var/lib/cfgms (identity, certs) and /opt/cfgms (versions).
set -eu

: "${VSTEWARD_CONTROLLER_URL:?VSTEWARD_CONTROLLER_URL is required}"

# Install root: seed the release version once; keep whatever the controller has
# pushed since.
if [ ! -f /opt/cfgms/state.json ]; then
    mkdir -p /opt/cfgms
    cp -a /usr/share/cfgms-seed/. /opt/cfgms/
fi

# Controller CA in the install-pinned location the steward reads.
mkdir -p /etc/cfgms
if [ -f /run/vsteward/controller-ca.crt ]; then
    install -m 0644 /run/vsteward/controller-ca.crt /etc/cfgms/controller-ca.crt
fi

# The steward accepts the token only from a regular, root-owned file with no group
# or other bits; a secret mount does not qualify, so copy it. The token is never
# printed or passed in argv.
mkdir -p /var/lib/cfgms
umask 077
if [ -f /run/secrets/regtoken ]; then
    cp /run/secrets/regtoken /var/lib/cfgms/regtoken.tmp
    chmod 0600 /var/lib/cfgms/regtoken.tmp
    mv /var/lib/cfgms/regtoken.tmp /var/lib/cfgms/regtoken
fi
if [ ! -s /var/lib/cfgms/regtoken ]; then
    echo "vsteward: no registration token at /run/secrets/regtoken" >&2
    exit 64
fi

exec /usr/local/bin/cfgms-launcher run --root /opt/cfgms \
    --child-args "--regtoken-file /var/lib/cfgms/regtoken --controller-url ${VSTEWARD_CONTROLLER_URL}"
