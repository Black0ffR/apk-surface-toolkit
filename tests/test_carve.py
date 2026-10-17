"""NA-01 regression tests. Synthetic byte fixtures only; no APK execution.

Contracts under test:
- carve.cascade_evidence(): every carved/decoded item carries source hash,
  offsets, lengths, transform details, decoded hash, candidate confidence.
- carve.redact()/looks_sensitive(): presentation redaction of likely
  secrets; source evidence bytes are never modified.
- XOR attempt cap and candidate budget bounds.
- run_cascade/extract legacy behavior preserved.
"""
from __future__ import annotations

import base64
import hashlib
import unittest

from triagekit import carve as CV
from triagekit import rules as R


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _recs(data: bytes, **kw) -> list[dict]:
    spans = CV.extract(data)
    kw.setdefault("library", "libfixture.so")
    kw.setdefault("source_artifact_sha256", _sha(data))
    return CV.cascade_evidence(data, spans, **kw)


class TestEvidenceRecords(unittest.TestCase):
    """cascade_evidence records follow the NA-01 output contract."""

    CONTRACT_KEYS = {
        "source_artifact_sha256", "library", "file_offset", "length",
        "encoding_or_transform", "transform_parameters", "decoded_sha256",
        "printable_ratio", "classification", "confidence", "validation",
    }

    def test_base64_whole_record_contract(self):
        secret = b"https://anchor.example/decoded-inner"
        data = b"junk-padding-" + base64.b64encode(secret) + b"-tail"
        recs = _recs(data)
        base = [r for r in recs
                if r["encoding_or_transform"].startswith("base64")]
        self.assertTrue(base, "no base64 record produced")
        r = base[0]
        for key in self.CONTRACT_KEYS:
            self.assertIn(key, r, f"missing contract key {key}")
        self.assertEqual(r["source_artifact_sha256"], _sha(data))
        self.assertEqual(r["encoding_or_transform"], "base64")
        self.assertIn(r["transform_parameters"]["variant"],
                      ("std", "url", "std-nopad", "url-nopad"))
        self.assertEqual(r["decoded_sha256"], _sha(secret))
        # offset anchors at the start of the matched blob
        self.assertEqual(data[r["file_offset"]:r["file_offset"] + 4],
                         base64.b64encode(secret)[:4])
        self.assertTrue(0.0 <= r["printable_ratio"] <= 1.0)
        self.assertEqual(r["classification"], "candidate-string")
        self.assertEqual(r["confidence"], "candidate")
        self.assertEqual(r["validation"], "not_runtime_verified")

    def test_hex_substring_offset_anchored(self):
        gs = b"SRC-OFFSET-CHECK"
        data = b"prefix-junk--" + gs.hex().encode() + b"--tail"
        recs = _recs(data)
        hexes = [r for r in recs if r["encoding_or_transform"] == "hex"]
        self.assertTrue(hexes, "no hex record produced")
        r = hexes[0]
        self.assertEqual(r["decoded_sha256"], _sha(gs))
        self.assertEqual(r["file_offset"], data.index(gs.hex().encode()))

    def test_xor_key_in_transform_parameters(self):
        msg = b"https:x--cap.example--only-key-contract"
        data = _xor(msg, 0x40)
        recs = _recs(data)
        x = [r for r in recs if r["encoding_or_transform"] == "xor-byte"]
        self.assertTrue(x, "xor-byte record missing")
        key = x[0]["transform_parameters"].get("key")
        self.assertIsInstance(key, int)
        # the recorded key must reproduce the recorded decoded hash
        self.assertEqual(x[0]["decoded_sha256"], _sha(_xor(data, key)))

    def test_dedup_by_decoded_hash(self):
        blob = base64.b64encode(b"https://dedup.example/once")
        data = blob + b" " + blob
        recs = _recs(data, include_raw=False)
        hashes = [r["decoded_sha256"] for r in recs]
        self.assertEqual(len(hashes), len(set(hashes)),
                         "duplicate decoded hashes in output")

    def test_budget_cap_with_truncation_sentinel(self):
        blobs = []
        for i in range(5):
            payload = b"https://budget.example/entry-%d" % i
            blobs.append(base64.b64encode(payload))
        data = b" ".join(blob for blob in blobs)
        recs = _recs(data, max_candidates=2)
        # count excludes the explicit truncation sentinel
        records = [r for r in recs if not r.get("truncated")]
        self.assertLessEqual(len(records), 2)
        self.assertEqual(len([r for r in recs if r.get("truncated")]), 1,
                         "truncation must be explicit")

    def test_sensitive_decoded_is_redacted(self):
        secret = b"AKIAIOSFODNN7EXAMPLE"
        data = base64.b64encode(secret)
        recs = _recs(data)
        b64 = [r for r in recs
               if r["encoding_or_transform"].startswith("base64")]
        self.assertTrue(b64, "no base64 record")
        # presentation hides the full value; evidence hash stays intact
        self.assertNotIn(secret.decode(), b64[0]["decoded_text_preview"])
        self.assertIn("redacted", b64[0]["decoded_text_preview"])
        self.assertEqual(b64[0]["decoded_sha256"], _sha(secret))

    def test_non_sensitive_preview_is_plain(self):
        secret = b"https://plain.example/visible-path"
        data = base64.b64encode(secret)
        recs = _recs(data)
        b64 = [r for r in recs
               if r["encoding_or_transform"].startswith("base64")]
        self.assertEqual(b64[0]["decoded_text_preview"], secret.decode())
        self.assertEqual(b64[0]["decoded_sha256"], _sha(secret))

    def test_raw_string_records_when_enabled(self):
        data = b"\x00\x00" + b"abcdefghijklmnop"
        recs = _recs(data, include_raw=True)
        raws = [r for r in recs if r["encoding_or_transform"] == "raw-string"]
        self.assertTrue(raws, "raw-string records expected")
        r = raws[0]
        self.assertEqual(r["transform_parameters"], {})
        self.assertEqual(r["file_offset"], 2)
        self.assertEqual(r["length"], 16)
        self.assertEqual(r["decoded_sha256"], _sha(b"abcdefghijklmnop"))
        self.assertEqual(r["classification"], "candidate-string")

    def test_utf16_offsets_are_byte_correct(self):
        text = "https://utf.example/u"
        data = b"ab" + text.encode("utf-16-le")
        recs = _recs(data, include_raw=True)
        raws = [r for r in recs if r["encoding_or_transform"] == "raw-string"
                and r["length"] >= 20]
        self.assertTrue(raws, "utf-16 raw record expected")
        self.assertEqual(raws[0]["file_offset"], 2)
        self.assertEqual(raws[0]["length"], len(text) * 2)
        self.assertEqual(raws[0]["decoded_sha256"],
                         _sha(text.encode("utf-16-le")))


class TestXorCap(unittest.TestCase):
    def test_cap_limited_keys(self):
        msg = b"https://cap.example/only-key-55-works"
        enc = _xor(msg, 0x37).replace(b"\x00", b" ")  # stay printable
        cas = list(CV.cascade(enc.decode("latin-1"), max_xor_keys=10))
        self.assertEqual([t for t, _ in cas if t == "xor1"], [])
        cas_full = list(CV.cascade(enc.decode("latin-1")))
        self.assertIn("xor1", [t for t, _ in cas_full])

    def test_legacy_cascade_and_run_cascade_unchanged(self):
        data = base64.b64encode(b"tx-hello-cascade-world!")
        cas = list(CV.cascade(data.decode()))
        self.assertTrue(all(isinstance(d, bytes) for _, d in cas))
        out = CV.run_cascade([data.decode()], max_candidates=5)
        self.assertTrue(out and "transform" in out[0] and "decoded" in out[0])


class TestRedaction(unittest.TestCase):
    def test_redact_format_keeps_hash(self):
        v = "AKIAIOSFODNN7EXAMPLE"
        red = CV.redact(v)
        self.assertNotIn(v, red)
        self.assertIn(v[:6], red[:8])
        self.assertIn(_sha(v.encode())[:16], red)

    def test_looks_sensitive_shapes(self):
        self.assertTrue(CV.looks_sensitive("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(CV.looks_sensitive("xoxb-123456789-abcdef"))
        self.assertTrue(CV.looks_sensitive("-----BEGIN RSA PRIVATE KEY-----"))
        self.assertFalse(CV.looks_sensitive("https://plain.example/ok"))
        # long low-entropy token stays non-sensitive
        self.assertFalse(CV.looks_sensitive("AAAAAAAAAAAAAAAAAAAA"))


class TestCheckNativeProvenance(unittest.TestCase):
    """check_native findings carry NA-01 provenance detail (no behavior
    change to which rules fire)."""

    def _rule(self, rid: str) -> R.Rule:
        return R.Rule({"id": rid, "title": rid, "kind": "regex",
                       "severity": "info", "check": "keyword", "params": {}})

    def test_provenance_on_raw_and_decoded_findings(self):
        import hashlib
        import io as _io
        import os as _os
        import tempfile as _tempfile
        import zipfile as _zipfile
        from triagekit import analyzer as AN

        inner = b"https://hidden.example/decoded-endpoint"
        url = b"https://visible.example/collect"
        lib = b"\x00junk\x00" + url + b" " + base64.b64encode(inner)
        with _tempfile.TemporaryDirectory() as td:
            buf = _io.BytesIO()
            with _zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("lib/arm64-v8a/libt.so", lib)
            p = _os.path.join(td, "fixture.apk")
            with open(p, "wb") as f:
                f.write(buf.getvalue())
            stats = {}
            findings = AN.check_native(
                {"AS-0021": self._rule("AS-0021"),
                 "AS-0016": self._rule("AS-0016")},
                p, limit=25, stats=stats)
        self.assertEqual(stats["files_scanned"], 1)
        self.assertEqual(stats["hits"], 2)
        self.assertFalse(stats["truncated_any"])
        raws = [f for f in findings if not f["detail"].get("carved")]
        decs = [f for f in findings if f["detail"].get("carved")]
        self.assertEqual(len(raws), 1, "one raw-URL finding expected")
        self.assertEqual(len(decs), 1, "one decoded finding expected")
        d = raws[0]["detail"]
        self.assertEqual(d["file_offset"], lib.index(url))
        # detail describes the carved span containing the hit
        self.assertEqual(d["length"], len(lib) - d["file_offset"])
        self.assertEqual(d["source_artifact_sha256"],
                         hashlib.sha256(lib).hexdigest())
        dd = decs[0]["detail"]
        self.assertEqual(dd["transform"], "base64-std")
        self.assertEqual(dd["transform_parameters"], {"variant": "std"})
        self.assertEqual(dd["decoded_sha256"], hashlib.sha256(inner).hexdigest())
        self.assertTrue(dd["file_offset"] > lib.index(url))
        self.assertLessEqual(dd["file_offset"] + dd["length"], len(lib))
        for f in (raws[0], decs[0]):
            self.assertEqual(f["detail"]["classification"], "candidate-string")
            self.assertEqual(f["detail"]["confidence"], "candidate")
            self.assertEqual(f["detail"]["validation"], "not_runtime_verified")


class TestCheckNativeCaps(unittest.TestCase):
    """Every check_native cap is counted and makes the native stage partial.

    F4: silent input caps must surface as truncation statistics, never as an
    apparently complete scan.
    """

    def _rule(self, rid: str) -> R.Rule:
        return R.Rule({"id": rid, "title": rid, "kind": "regex",
                       "severity": "info", "check": "keyword", "params": {}})

    def _native_stage(self, stats: dict) -> dict:
        from triagekit import analyzer as AN
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=True,
            kinds_present={"manifest", "regex"}, native_stats=stats,
            regex_stats={"truncated_any": False})
        return next(s for s in stages if s["stage"] == "native")

    def _apk(self, td: str, entries: list) -> str:
        import os
        import zipfile
        p = os.path.join(td, "fixture.apk")
        with zipfile.ZipFile(p, "w") as zf:
            for name, body in entries:
                zf.writestr(name, body)
        return p

    def test_libraries_beyond_file_cap_are_counted(self):
        import tempfile
        from triagekit import analyzer as AN
        entries = [(f"lib/arm64-v8a/libl{i:02d}.so",
                    b"\x00junk\x00http://x%d.example/collect" % i)
                   for i in range(25)]
        with tempfile.TemporaryDirectory() as td:
            apk = self._apk(td, entries)
            stats: dict = {}
            AN.check_native({"AS-0021": self._rule("AS-0021")}, apk,
                            limit=1000, stats=stats)
        self.assertEqual(stats["files_scanned"], 20)
        self.assertEqual(stats["files_skipped"], 5)
        stage = self._native_stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("cap", stage["reason"].lower())

    def test_oversized_library_is_counted_truncated(self):
        import tempfile
        from triagekit import analyzer as AN
        with tempfile.TemporaryDirectory() as td:
            apk = self._apk(td, [("lib/arm64-v8a/libbig.so",
                                  b"\x00" * 8_000_001)])
            stats: dict = {}
            AN.check_native({"AS-0021": self._rule("AS-0021")}, apk,
                            limit=1000, stats=stats)
        self.assertEqual(stats["files_truncated"], 1)
        stage = self._native_stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("truncat", stage["reason"].lower())

    def test_unreadable_entry_is_counted(self):
        import tempfile
        import zipfile
        from unittest import mock
        from triagekit import analyzer as AN
        orig = zipfile.ZipFile.read

        def flaky(zf, name, *a, **k):
            if str(name).endswith("libbad.so"):
                raise RuntimeError("boom")
            return orig(zf, name, *a, **k)

        with tempfile.TemporaryDirectory() as td:
            apk = self._apk(td, [
                ("lib/arm64-v8a/libgood.so", b"\x00junk\x00http://ok.example/x"),
                ("lib/arm64-v8a/libbad.so", b"\x00junk\x00http://bad.example/x"),
            ])
            stats: dict = {}
            with mock.patch.object(zipfile.ZipFile, "read", flaky):
                AN.check_native({"AS-0021": self._rule("AS-0021")}, apk,
                                limit=1000, stats=stats)
        self.assertEqual(stats["read_errors"], 1)
        self.assertEqual(stats["files_scanned"], 1)
        stage = self._native_stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("unreadable", stage["reason"].lower())

    def test_carve_failure_is_counted(self):
        import tempfile
        from unittest import mock
        from triagekit import analyzer as AN
        with tempfile.TemporaryDirectory() as td:
            apk = self._apk(td, [("lib/arm64-v8a/libx.so",
                                  b"\x00junk\x00http://x.example/collect")])
            stats: dict = {}
            with mock.patch("triagekit.carve.extract",
                            side_effect=RuntimeError("carve boom")):
                AN.check_native({"AS-0021": self._rule("AS-0021")}, apk,
                                limit=1000, stats=stats)
        self.assertEqual(stats["carve_errors"], 1)
        stage = self._native_stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("carve", stage["reason"].lower())
