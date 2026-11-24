#!/usr/bin/env python3
"""Tests for the build-time steward signature check.

Run: python3 testcell/tests/verify_steward_sig_test.py

Key-set and input-parsing tests use only the standard library. Signature tests use
pyca/cryptography (it is in the image's verify stage and in the tooling-tests
workflow). Outside CI they are skipped when it is missing; with CI set, a missing
pyca/cryptography fails the run.
"""

from __future__ import annotations

import base64
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load" / "image"))

import verify_steward_sig as v  # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - depends on the environment
    if os.environ.get("CI"):
        raise SystemExit("verify_steward_sig_test: pyca/cryptography is required in CI")
    HAVE_CRYPTO = False

ORDER8_A = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
ORDER8_B = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"


def b64(raw):
    return base64.b64encode(raw).decode()


def high(first):
    return bytes([first]) + b"\xff" * 30 + b"\x7f"


UNSAFE = {
    "all-zero placeholder": bytes(32),
    "identity": bytes([1]) + bytes(31),
    "order-8 a": bytes.fromhex(ORDER8_A),
    "order-8 b": bytes.fromhex(ORDER8_B),
    "p-1": high(0xEC),
    "p": high(0xED),
    "p+1": high(0xEE),
}


class UnsafeKeyTest(unittest.TestCase):
    def test_every_small_order_key_is_refused_in_both_sign_variants(self):
        for name, key in UNSAFE.items():
            for variant in (key, key[:-1] + bytes([key[-1] | 0x80])):
                with self.subTest(name=name, sign=variant[-1] >> 7):
                    self.assertTrue(v.is_unsafe_key(variant))
                    with self.assertRaises(v.BadInput):
                        v.parse_key(b64(variant))

    def test_a_normal_key_is_accepted(self):
        key = bytes(range(1, 33))
        self.assertFalse(v.is_unsafe_key(key))
        self.assertEqual(v.parse_key(b64(key)), key)

    def test_key_base64_is_strict(self):
        good = b64(bytes(range(1, 33)))
        for bad in (good[:10] + "!" + good[10:], good[:-4], "not base64 at all"):
            with self.subTest(bad=bad), self.assertRaises(v.BadInput):
                v.parse_key(bad)


class InputTest(unittest.TestCase):
    def test_signature_accepts_raw_and_base64url_forms(self):
        raw = bytes(range(64))
        self.assertEqual(v.parse_signature(raw), raw)
        text = base64.urlsafe_b64encode(raw).rstrip(b"=") + b"\n"
        self.assertEqual(v.parse_signature(text), raw)

    def test_signature_of_the_wrong_length_or_alphabet_is_refused(self):
        good = base64.urlsafe_b64encode(bytes(range(64))).rstrip(b"=")
        plus = good[:20] + b"+" + good[21:]
        space = good[:40] + b" " + good[40:]
        for bad in (bytes(63), b"AAAA", b"\xff\xfe not text", plus, space):
            with self.subTest(bad=bad), self.assertRaises(v.BadInput):
                v.parse_signature(bad)

    def test_version_must_be_semver(self):
        self.assertTrue(v.message("h", "v0.10.8-lab.3767.gf9494beb", "linux", "amd64"))
        self.assertEqual(v.message("h", "1.2.3", "linux", "amd64"), b"h|v1.2.3|linux|amd64")
        self.assertTrue(v.message("h", "1.2.3-rc.0", "linux", "amd64"))
        for bad in ("1.2.3-01", "1.2.3-rc.01", "1.2", "v1.2.3/../x", "1.2.3 extra", "01.2.3", "v1.2.3|x", "1.2.3\n"):
            with self.subTest(bad=bad), self.assertRaises(v.BadInput):
                v.message("h", bad, "linux", "amd64")


@unittest.skipUnless(HAVE_CRYPTO, "pyca/cryptography not installed")
class SignatureTest(unittest.TestCase):
    def setUp(self):
        self.sk = Ed25519PrivateKey.generate()
        pub = self.sk.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
        self.pub = b64(pub)
        self.binary = b"steward binary bytes"
        import hashlib
        self.msg = v.message(hashlib.sha256(self.binary).hexdigest(), "v1.2.3", "linux", "amd64")

    def test_raw_and_text_signatures_verify(self):
        sig = self.sk.sign(self.msg)
        self.assertTrue(v.verify(self.binary, sig, "1.2.3", "linux", "amd64", self.pub))
        text = base64.urlsafe_b64encode(sig).rstrip(b"=")
        self.assertTrue(v.verify(self.binary, text, "v1.2.3", "linux", "amd64", self.pub))

    def test_a_changed_binary_or_coordinate_does_not_verify(self):
        sig = self.sk.sign(self.msg)
        self.assertFalse(v.verify(self.binary + b"x", sig, "1.2.3", "linux", "amd64", self.pub))
        self.assertFalse(v.verify(self.binary, sig, "1.2.4", "linux", "amd64", self.pub))
        self.assertFalse(v.verify(self.binary, sig, "1.2.3", "linux", "arm64", self.pub))

    def test_a_forged_signature_against_a_small_order_key_is_refused_before_verify(self):
        # Forgeries R || S with S = 0 and R a small-order point verify against
        # small-order keys in some Ed25519 implementations; every pairing of key and
        # R is refused before verification.
        for key_name, key in UNSAFE.items():
            for r_name, r in UNSAFE.items():
                with self.subTest(key=key_name, r=r_name), self.assertRaises(v.BadInput):
                    v.verify(self.binary, r + bytes(32), "1.2.3", "linux", "amd64", b64(key))


if __name__ == "__main__":
    unittest.main()
