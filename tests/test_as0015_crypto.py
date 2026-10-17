"""Batch J P1: AS-0015 intended semantics for both crypto branches.

The shipped pattern's first branch (``Cipher.getInstance``) could never match
a working literal: it required a doubled quote after the algorithm, so both
the bare ``"AES"`` form (ECB by default - the rule's own recommendation says
so) and the explicit ``"AES/ECB/..."`` form were missed. These cases pin the
intended behavior per branch against the shipped rule. Assertions compile the
rule's real pattern with the same flags as analyzer.check_regex.
"""
from __future__ import annotations

import os
import re
import unittest

from triagekit import rules as R

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SHIPPED, _ = R.load_dir(os.path.join(ROOT, "rules"))
AS_0015 = next(r for r in SHIPPED if r.id == "AS-0015")
RX = re.compile(AS_0015.params["pattern"], re.I)

MUST_MATCH = {
    "cipher_bare_aes": 'javax.crypto.Cipher.getInstance("AES");',
    "cipher_bare_blowfish": 'Cipher.getInstance("Blowfish");',
    "cipher_bare_des": 'Cipher.getInstance("DES");',
    "cipher_ecb_with_padding": 'Cipher.getInstance("AES/ECB/PKCS5Padding");',
    "cipher_ecb_no_padding": 'Cipher.getInstance("AES/ECB");',
    "message_digest_md5": 'MessageDigest.getInstance("MD5");',
    "message_digest_sha1_dash": 'MessageDigest.getInstance("SHA-1");',
    "message_digest_sha1_plain": 'MessageDigest.getInstance("SHA1");',
    "iv_parameter_spec_use": "new IvParameterSpec(ivBytes);",
    "secret_key_spec_use": 'new SecretKeySpec(keyBytes, "AES");',
    "securerandom_setseed": "new SecureRandom().setSeed(seed);",
}

MUST_NOT_MATCH = {
    "cipher_gcm": 'Cipher.getInstance("AES/GCM/NoPadding");',
    "cipher_cbc": 'Cipher.getInstance("AES/CBC/PKCS5Padding");',
    "cipher_rsa_ecb": 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");',
    "cipher_chacha20": 'Cipher.getInstance("ChaCha20-Poly1305");',
    "message_digest_sha256": 'MessageDigest.getInstance("SHA-256");',
    "message_digest_sha512": 'MessageDigest.getInstance("SHA-512");',
}


class TestAS0015Branches(unittest.TestCase):
    def test_intended_matches(self):
        for name, line in MUST_MATCH.items():
            with self.subTest(case=name):
                self.assertTrue(RX.search(line), f"{name}: {line!r}")

    def test_clean_constructs_stay_unmatched(self):
        for name, line in MUST_NOT_MATCH.items():
            with self.subTest(case=name):
                self.assertFalse(RX.search(line), f"{name}: {line!r}")


if __name__ == "__main__":
    unittest.main()
