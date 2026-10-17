"""Batch J P1: network-security-config parsing contract.

The shipped parser only understood the non-canonical
``<trust-anchors><anchors src="..."/></trust-anchors>`` dialect. These tests
pin the canonical Android schema (``<trust-anchors><certificates src="..."/>``)
for every container kind, keep the legacy dialect working, and require that
configs we cannot interpret are distinguishable from configs with no user CA
at all ("absent" vs "unsupported/malformed"). Decoded-tree XML and in-memory
zips only; no APK execution.
"""
from __future__ import annotations

import os
import tempfile
import unittest
import zipfile

from triagekit import analyzer as AN
from triagekit import manifest as MF
from triagekit import report as RP
from triagekit import rules as R

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SHIPPED, _ = R.load_dir(os.path.join(ROOT, "rules"))
AS_0029 = next(r for r in SHIPPED if r.id == "AS-0029")
AS_0030 = next(r for r in SHIPPED if r.id == "AS-0030")

CANONICAL_BASE_USER = """\
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
"""

LEGACY_BASE_USER = """\
<network-security-config>
    <base-config>
        <trust-anchors>
            <anchors src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
"""

CANONICAL_DOMAIN_USER = """\
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">example.com</domain>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </domain-config>
</network-security-config>
"""

CANONICAL_DEBUG_OVERRIDES_USER = """\
<network-security-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

MIXED_DIALECTS = """\
<network-security-config>
    <base-config>
        <trust-anchors>
            <anchors src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
"""

UNKNOWN_TRUST_CHILDREN = """\
<network-security-config>
    <base-config>
        <trust-anchors>
            <mystery src="user"/>
            <certificates/>
        </trust-anchors>
    </base-config>
</network-security-config>
"""

ABSENT_TRUST_ANCHORS = """\
<network-security-config>
    <base-config cleartextTrafficPermitted="false"/>
</network-security-config>
"""


def _read(xml: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "res", "xml", "network_security_config.xml")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(xml)
        return MF.read_network_security_config(td)


def _findings(records: list[dict]) -> list[dict]:
    return AN.check_manifest([AS_0029], {"package": "com.example.app"},
                             records, set(), [], None, [])


def _base_domain(records: list[dict]) -> dict:
    return next(d for d in records[0]["domains"] if d["kind"] == "base-config")


class TestCanonicalTrustAnchors(unittest.TestCase):
    def test_canonical_base_config_user_ca_detected(self):
        recs = _read(CANONICAL_BASE_USER)
        dom = _base_domain(recs)
        self.assertEqual(dom["trust_anchors"], ["system", "user"], dom)
        out = _findings(recs)
        self.assertEqual(len(out), 1, out)
        self.assertIn("user trust anchors in base-config", out[0]["evidence"])

    def test_canonical_domain_config_user_ca_detected(self):
        recs = _read(CANONICAL_DOMAIN_USER)
        dom = recs[0]["domains"][0]
        self.assertEqual(dom["kind"], "domain-config")
        self.assertEqual(dom["trust_anchors"], ["user"], dom)
        out = _findings(recs)
        self.assertEqual(len(out), 1, out)
        self.assertIn("user trust anchors in domain-config", out[0]["evidence"])

    def test_canonical_debug_overrides_user_ca_detected(self):
        recs = _read(CANONICAL_DEBUG_OVERRIDES_USER)
        dom = recs[0]["domains"][0]
        self.assertEqual(dom["kind"], "debug-overrides")
        self.assertEqual(dom["trust_anchors"], ["user"], dom)
        self.assertEqual(len(_findings(recs)), 1)

    def test_mixed_dialects_merged_in_document_order(self):
        dom = _base_domain(_read(MIXED_DIALECTS))
        self.assertEqual(dom["trust_anchors"], ["system", "user"], dom)


class TestLegacyAndAbsent(unittest.TestCase):
    def test_legacy_anchors_dialect_still_parsed(self):
        dom = _base_domain(_read(LEGACY_BASE_USER))
        self.assertEqual(dom["trust_anchors"], ["user"], dom)
        self.assertEqual(len(_findings(_read(LEGACY_BASE_USER))), 1)

    def test_absent_trust_anchors_stay_clean_and_unflagged(self):
        recs = _read(ABSENT_TRUST_ANCHORS)
        dom = _base_domain(recs)
        self.assertNotIn("unknown_trust_anchors", dom)
        self.assertEqual(_findings(recs), [])


class TestUnsupportedOrMalformed(unittest.TestCase):
    def test_uninterpreted_trust_children_are_recorded(self):
        dom = _base_domain(_read(UNKNOWN_TRUST_CHILDREN))
        self.assertEqual(dom["unknown_trust_anchors"],
                         ["mystery", "certificates(missing src)"], dom)

    def test_uninterpreted_trust_children_surface_as_finding(self):
        out = _findings(_read(UNKNOWN_TRUST_CHILDREN))
        self.assertEqual(len(out), 1, out)
        self.assertIn("user trust cannot be excluded", out[0]["evidence"])
        self.assertIn("mystery", out[0]["evidence"])

    def test_content_scan_surfaces_unparseable_config_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            apk = os.path.join(td, "app.apk")
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("res/obf7.xml",
                           b"\xff\xff\xff\xffnetwork-security-config\x00garbage")
                z.writestr("res/other.xml", b"<resources/>")
            recs = MF.find_network_security_config(apk)
        self.assertEqual(len(recs), 1, recs)
        self.assertTrue(recs[0]["parse_error"])
        self.assertEqual(recs[0]["file"], "res/obf7.xml")

    def test_content_scan_ignores_files_without_the_marker(self):
        with tempfile.TemporaryDirectory() as td:
            apk = os.path.join(td, "app.apk")
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("res/plain.xml", b"<resources/>")
            self.assertEqual(MF.find_network_security_config(apk), [])


class TestParseErrorSurfacing(unittest.TestCase):
    """F8: an unreadable NSC must not produce absence claims, and must surface."""

    def test_parse_error_record_yields_no_no_pinning_claim(self):
        recs = [{"file": "res/xml/obf7.xml", "parse_error": True,
                 "source": "content-scan", "raw": "garbage"}]
        out = AN.check_manifest([AS_0030], {"package": "com.example.app"},
                                recs, set(), [], None, [])
        self.assertEqual(out, [])

    def test_blind_finding_for_parse_error_records(self):
        out = AN.nsc_blind_findings([{"file": "res/xml/obf7.xml",
                                      "parse_error": True}])
        self.assertEqual([f["rule"] for f in out], ["BLIND-0004"])
        self.assertIn("obf7.xml", " ".join(f["evidence"] for f in out))

    def test_no_blind_finding_without_parse_errors(self):
        self.assertEqual(AN.nsc_blind_findings(
            [{"file": "res/xml/a.xml", "domains": []}]), [])
        self.assertEqual(AN.nsc_blind_findings([]), [])

    def test_report_renders_unparseable_warning(self):
        md = RP.render({"findings": [], "network_security_config": [
            {"file": "res/xml/obf7.xml", "parse_error": True, "raw": "garbage"}]})
        self.assertIn("unparseable", md.lower())
        self.assertIn("obf7.xml", md)


if __name__ == "__main__":
    unittest.main()
