#!/usr/bin/env python3
"""Verify a steward binary's publisher signature at image build time.

The signature is Ed25519 over the canonical steward-binary message that the
steward and controller use (cfgms pkg/modules/trust StewardBinaryMessage):

    <sha256 hex of the binary>|<version with a leading "v">|<platform>|<arch>

The signature file holds base64url (unpadded) text; the public key is the
standard-base64 32-byte Ed25519 key that is baked into the steward.

Usage: verify_steward_sig.py <binary> <sig-file> <version> <platform> <arch> <pubkey-b64>
Exit 0 when the signature verifies, 1 otherwise.
"""

import base64
import hashlib
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SEP = "|"


def message(content_hash, version, platform, arch):
    for name, value in (("content hash", content_hash), ("version", version),
                        ("platform", platform), ("arch", arch)):
        if not value or SEP in value:
            raise ValueError(f"invalid {name}")
    if not version.startswith("v"):
        version = "v" + version
    return SEP.join((content_hash, version, platform, arch)).encode()


def b64url_decode(text):
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def main(argv):
    if len(argv) != 7:
        print(__doc__.splitlines()[-2], file=sys.stderr)
        return 2
    binary, sig_file, version, platform, arch, pub_b64 = argv[1:]
    h = hashlib.sha256()
    with open(binary, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    with open(sig_file) as f:
        sig = b64url_decode(f.read())
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
    try:
        key.verify(sig, message(h.hexdigest(), version, platform, arch))
    except InvalidSignature:
        print("steward signature does not verify", file=sys.stderr)
        return 1
    print("steward signature verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
