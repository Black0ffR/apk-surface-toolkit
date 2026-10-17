"""Batch J P2: the real APK signature path, end to end.

No APK is ever executed. The fixtures' ``sig.json`` bypasses
``apktools.signature()``; here we build a genuinely signed APK with the
on-device toolchain (aapt + keytool + apksigner all perform static,
read-only parsing/cryptography) and validate:

  * ``signature()`` parses the real ``apksigner verify --print-certs``
    output (scheme flags, certificate DN, SHA-256),
  * the AS-0028 analyzer branches (debug cert, v1-only Janus window)
    consume that real dict,
  * the error path for a zip that is not a valid APK.

What this does NOT prove: anything about the signer's identity beyond the
self-signed test certs, and anything requiring APK execution.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from triagekit import analyzer as AN
from triagekit import apktools as AT
from triagekit import manifest as MF
from triagekit import rules as R

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SHIPPED, _ = R.load_dir(os.path.join(ROOT, "rules"))
AS_0028 = next(r for r in SHIPPED if r.id == "AS-0028")

FRAMEWORK = "/system/framework/framework-res.apk"
TOOLS = ("aapt", "keytool", "apksigner")
HAVE_TOOLS = (all(shutil.which(t) for t in TOOLS)
              and os.path.isfile(FRAMEWORK))

STORE_PW = "android"
RELEASE_DN = "CN=Release Fixture, O=TriageKit, C=US"
DEBUG_DN = "CN=Android Debug, O=Android, C=US"

# minSdk 21 in the signed APK: apksigner only emits v1 signatures when the
# APK targets below API 24, so 24+ would make a "v1+v2" artifact impossible.
# The analyzer's minSdk input is separately controlled via decoded trees.
MANIFEST_XML = """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android" \
package="com.example.sigfixture">
    <uses-sdk android:minSdkVersion="21"/>
    <application android:label="Fixture"/>
</manifest>
"""


def _sh(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          timeout=300)


def _decoded_tree(td: str, min_sdk: int) -> str:
    tree = os.path.join(td, f"decoded_sdk{min_sdk}")
    os.makedirs(tree, exist_ok=True)
    with open(os.path.join(tree, "AndroidManifest.xml"), "w",
              encoding="utf-8") as fh:
        fh.write(MANIFEST_XML.replace('minSdkVersion="21"',
                                      f'minSdkVersion="{min_sdk}"'))
    return tree


def _check(tree: str, sig: dict) -> list[dict]:
    man = MF.parse(os.path.join(tree, "AndroidManifest.xml"))
    return AN.check_manifest([AS_0028], man, [], set(), [], sig, [])


@unittest.skipUnless(HAVE_TOOLS,
                     "needs aapt + keytool + apksigner + framework-res.apk")
class TestRealSignaturePath(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        td = cls._tmp.name
        manifest = os.path.join(td, "AndroidManifest.xml")
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write(MANIFEST_XML)
        base = os.path.join(td, "base.apk")
        r = _sh(["aapt", "package", "-f", "-I", FRAMEWORK, "-M", manifest,
                 "-F", base])
        if r.returncode != 0:
            raise AssertionError(f"aapt package failed: {r.stdout} {r.stderr}")
        for alias, dn in (("release", RELEASE_DN), ("debug", DEBUG_DN)):
            r = _sh(["keytool", "-genkeypair", "-keystore",
                     os.path.join(td, f"ks_{alias}.p12"), "-storetype",
                     "PKCS12", "-alias", alias, "-keyalg", "RSA", "-keysize",
                     "2048", "-dname", dn, "-validity", "2", "-storepass",
                     STORE_PW, "-keypass", STORE_PW])
            if r.returncode != 0:
                raise AssertionError(f"keytool failed: {r.stdout} {r.stderr}")
        cls.apks = {}
        for name, alias, v1, v2 in (("release_v1v2", "release", "true", "true"),
                                    ("release_v1only", "release", "true", "false"),
                                    ("debug_v1v2", "debug", "true", "true")):
            out = os.path.join(td, name + ".apk")
            r = _sh(["apksigner", "sign", "--ks",
                     os.path.join(td, f"ks_{alias}.p12"), "--ks-pass",
                     f"pass:{STORE_PW}", "--key-pass", f"pass:{STORE_PW}",
                     "--ks-key-alias", alias, "--v1-signing-enabled", v1,
                     "--v2-signing-enabled", v2, "--v3-signing-enabled",
                     "false", "--out", out, base])
            if r.returncode != 0:
                raise AssertionError(f"apksigner sign failed for {name}: "
                                     f"{r.stdout} {r.stderr}")
            cls.apks[name] = out
        cls.td = td

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_signature_parses_schemes_dn_and_digest(self):
        sig = AT.signature(self.apks["release_v1v2"])
        self.assertTrue(sig["ok"], sig)
        self.assertTrue(sig["v1"], sig)
        self.assertTrue(sig["v2"], sig)
        self.assertFalse(sig["v3"], sig)
        self.assertEqual(sig.get("dn"), RELEASE_DN)
        sha = sig.get("sha256") or ""
        self.assertEqual(len(sha), 64, sig)
        int(sha, 16)

    def test_release_signature_is_clean_through_analyzer(self):
        sig = AT.signature(self.apks["release_v1v2"])
        self.assertEqual(_check(_decoded_tree(self.td, 24), sig), [])

    def test_v1_only_signature_is_janus_window_through_analyzer(self):
        sig = AT.signature(self.apks["release_v1only"])
        self.assertTrue(sig["ok"], sig)
        self.assertTrue(sig["v1"], sig)
        self.assertFalse(sig["v2"], sig)
        self.assertEqual(sig.get("dn"), RELEASE_DN)
        out = _check(_decoded_tree(self.td, 24), sig)
        self.assertEqual(len(out), 1, out)
        self.assertIn("v1-only signature with minSdk 24", out[0]["evidence"])
        self.assertEqual(_check(_decoded_tree(self.td, 28), sig), [])

    def test_debug_certificate_is_flagged_through_analyzer(self):
        sig = AT.signature(self.apks["debug_v1v2"])
        self.assertTrue(sig["ok"], sig)
        self.assertIn("CN=Android Debug", sig.get("dn") or "")
        out = _check(_decoded_tree(self.td, 24), sig)
        self.assertEqual(len(out), 1, out)
        self.assertIn("signed with debug certificate", out[0]["evidence"])

    def test_zip_without_manifest_is_reported_not_verified(self):
        bad = os.path.join(self.td, "not_an_apk.zip")
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("hello.txt", b"hi")
        sig = AT.signature(bad)
        self.assertFalse(sig["ok"], sig)
        self.assertIn("AndroidManifest.xml", sig.get("note", ""))


if __name__ == "__main__":
    unittest.main()
