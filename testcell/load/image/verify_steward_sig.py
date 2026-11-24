#!/usr/bin/env python3
"""Verify a steward binary's publisher signature at image build time.

The signature is Ed25519 over the canonical steward-binary message that the
steward and controller use (cfgms pkg/modules/trust StewardBinaryMessage):

    <sha256 hex of the binary>|<version with a leading "v">|<platform>|<arch>

The signature file is either the raw 64 signature bytes (what the product's
steward-binary signer writes) or the same bytes as base64url text. The public key
is the standard-base64 32-byte Ed25519 key baked into the steward. Keys that cannot
anchor trust are refused before anything is verified: the all-zero placeholder of
unconfigured builds and every other small-order point, ignoring the sign bit, the
same set the product refuses (pkg/modules/trust isUnsafePublisherKey).

The version must be a complete SemVer 2.0 value with an optional leading "v"
(cfgms pkg/version).

Usage: verify_steward_sig.py <binary> <sig-file> <version> <platform> <arch> <pubkey-b64>
Exit 0 when the signature verifies, 1 when it does not, 2 on bad input.
"""

import base64
import binascii
import hashlib
import re
import sys

SEP = "|"
B64URL = re.compile(r"[A-Za-z0-9_-]+")
KEY_SIZE = 32
SIG_SIZE = 64

SEMVER = re.compile(
    r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def _small_order_encodings():
    """Ed25519 encodings (sign bit cleared) of the points of order 1, 2, 4 and 8."""
    zero = bytes(KEY_SIZE)                       # order 4; the all-zero placeholder
    identity = bytes([1]) + bytes(KEY_SIZE - 1)  # order 1
    order8_a = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
    order8_b = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
    # p-1 (order 2), p (order 4), p+1 (order 1): first byte varies, then 0xff..., 0x7f.
    high = [bytes([first]) + b"\xff" * (KEY_SIZE - 2) + b"\x7f" for first in (0xEC, 0xED, 0xEE)]
    return frozenset([zero, identity, order8_a, order8_b] + high)


SMALL_ORDER = _small_order_encodings()


class BadInput(Exception):
    pass


def is_unsafe_key(pub):
    if len(pub) != KEY_SIZE:
        return False
    masked = pub[:-1] + bytes([pub[-1] & 0x7F])
    return masked in SMALL_ORDER


def parse_key(pub_b64):
    try:
        pub = base64.b64decode(pub_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise BadInput(f"public key is not valid base64: {e}") from e
    if len(pub) != KEY_SIZE:
        raise BadInput(f"public key is {len(pub)} bytes, want {KEY_SIZE}")
    if is_unsafe_key(pub):
        raise BadInput("public key is a small-order or placeholder key and cannot anchor trust")
    return pub


def parse_signature(data):
    if len(data) == SIG_SIZE:
        return data
    try:
        text = data.decode("ascii").strip()
        if not B64URL.fullmatch(text):
            raise ValueError("not base64url")
        sig = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (UnicodeDecodeError, binascii.Error, ValueError) as e:
        raise BadInput("signature is neither 64 raw bytes nor base64url text") from e
    if len(sig) != SIG_SIZE:
        raise BadInput(f"signature is {len(sig)} bytes, want {SIG_SIZE}")
    return sig


def message(content_hash, version, platform, arch):
    m = SEMVER.fullmatch(version)
    if not m:
        raise BadInput("version is not a SemVer 2.0 value")
    # SemVer 2.0: numeric pre-release identifiers carry no leading zeros.
    for ident in (m.group(4) or "").split("."):
        if ident.isdigit() and len(ident) > 1 and ident.startswith("0"):
            raise BadInput("version has a numeric pre-release identifier with a leading zero")
    for name, value in (("content hash", content_hash), ("version", version),
                        ("platform", platform), ("arch", arch)):
        if not value or SEP in value:
            raise BadInput(f"invalid {name}")
    if not version.startswith("v"):
        version = "v" + version
    return SEP.join((content_hash, version, platform, arch)).encode()


def verify(binary_bytes, sig_bytes, version, platform, arch, pub_b64):
    """True when the signature verifies; raises BadInput on unusable input."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = Ed25519PublicKey.from_public_bytes(parse_key(pub_b64))
    sig = parse_signature(sig_bytes)
    msg = message(hashlib.sha256(binary_bytes).hexdigest(), version, platform, arch)
    try:
        key.verify(sig, msg)
    except InvalidSignature:
        return False
    return True


def main(argv):
    if len(argv) != 7:
        print(__doc__.splitlines()[-2], file=sys.stderr)
        return 2
    binary, sig_file, version, platform, arch, pub_b64 = argv[1:]
    with open(binary, "rb") as f:
        data = f.read()
    with open(sig_file, "rb") as f:
        sig = f.read()
    try:
        ok = verify(data, sig, version, platform, arch, pub_b64)
    except BadInput as e:
        print(f"steward signature check refused: {e}", file=sys.stderr)
        return 2
    if not ok:
        print("steward signature does not verify", file=sys.stderr)
        return 1
    print("steward signature verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
