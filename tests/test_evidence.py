"""EV-01 tests: report provenance blocks, stable finding identity, evidence_items.

Covers plan §11: schema_version / run / artifact blocks, observation-vs-
interpretation evidence items with provenance and limitations, stable
finding identities that exclude volatile run metadata, redaction of
presentation fields, and preservation of every legacy field.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest

from triagekit import evidence as EV


def make_finding(**kw) -> dict:
    f = {
        "id": "AS-0009", "tool": "apk-surface", "rule": "AS-0009",
        "title": "Exported provider", "severity": "high", "kind": "manifest",
        "component": "com.x/.P", "file": "", "evidence": "android:exported=true",
        "recommendation": "restrict", "maswe": "M1", "static_only": True,
        "verification": {"status": "unverified", "script": None},
    }
    f.update(kw)
    return f


def make_report(findings=None, **kw) -> dict:
    r = {
        "tool": "apk-surface", "version": "0.2.0", "generated_at": "2026-01-01T00:00:00Z",
        "apk_path": "/home/user/samples/app.apk", "apk_sha256": "a" * 64, "size": 12345,
        "analysis": {"status": "complete", "stages": {}, "limitations": []},
        "findings": findings if findings is not None else [],
    }
    r.update(kw)
    return r


class TestAttachMetadata(unittest.TestCase):
    def test_schema_run_artifact_blocks(self):
        r = make_report()
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        self.assertEqual(r["schema_version"], "2")
        self.assertEqual(set(r["run"]), {
            "run_id", "started_at", "completed_at", "tool_version",
            "python_version", "platform", "command"})
        self.assertEqual(r["run"]["started_at"], "T0")
        self.assertEqual(r["run"]["completed_at"], "T1")
        self.assertEqual(r["artifact"], {"path_label": "app.apk",
                                          "sha256": "a" * 64, "size_bytes": 12345})

    def test_artifact_label_is_basename_only(self):
        r = make_report(apk_path="/data/data/com.termux/files/home/secret-dir/x.apk")
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        self.assertEqual(r["artifact"]["path_label"], "x.apk")

    def test_run_command_defaults_empty(self):
        r = make_report()
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        self.assertEqual(r["run"]["command"], [])

    def test_run_command_sanitized(self):
        r = make_report()
        EV.attach_report_metadata(
            r, started_at="T0", completed_at="T1",
            command=["apk-surface", "analyze", "--token", "s3cr3t-abcdef123456",
                     "app.apk"])
        cmd = r["run"]["command"]
        self.assertIn("--token", cmd)
        self.assertIn("[redacted]", cmd)
        self.assertNotIn("s3cr3t-abcdef123456", cmd)

    def test_run_command_equals_form(self):
        self.assertEqual(EV.sanitize_command(["--password=hunter2x"]),
                         ["--password=[redacted]"])

    def test_run_command_no_secret_in_run_block(self):
        r = make_report()
        EV.attach_report_metadata(
            r, started_at="T0", completed_at="T1",
            command=["tool", "--header", "Authorization: Bearer AKIAIOSFODNN7EXAMPLE"])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(r["run"]))

    def test_run_command_attached_header_secret_redacted(self):
        out = EV.sanitize_command(
            ["tool", "-HAuthorization: Bearer s3cr3t-abcdef123456"])
        self.assertNotIn("s3cr3t-abcdef123456", " ".join(out))
        self.assertIn("-H[redacted]", out)

    def test_home_path_collapsed(self):
        home = os.path.expanduser("~")
        out = EV.sanitize_command([f"{home}/project/app.apk"])
        self.assertEqual(out, ["~/project/app.apk"])


class TestFindingIdentity(unittest.TestCase):
    def test_stable_across_run_metadata(self):
        f1, f2 = make_finding(), make_finding()
        r1 = make_report([f1], generated_at="A", apk_sha256="a" * 64)
        r2 = make_report([f2], generated_at="B", apk_sha256="b" * 64)
        EV.attach_report_metadata(r1, started_at="T0", completed_at="T1")
        EV.attach_report_metadata(r2, started_at="T2", completed_at="T3")
        self.assertEqual(f1["finding_id"], f2["finding_id"])
        self.assertNotEqual(r1["run"]["run_id"], r2["run"]["run_id"])

    def test_distinct_bases_distinct_ids(self):
        a, b, c = make_finding(), make_finding(component="com.x/.Q"), make_finding(
            file="x.smali", detail={"line": 7})
        r = make_report([a, b, c])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        self.assertEqual(len({a["finding_id"], b["finding_id"], c["finding_id"]}), 3)

    def test_duplicate_basis_suffix(self):
        a, b = make_finding(), make_finding()
        r = make_report([a, b])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        self.assertNotEqual(a["finding_id"], b["finding_id"])
        self.assertTrue(b["finding_id"].endswith("-2"))

    def test_id_excludes_artifact_hash(self):
        f = make_finding()
        r = make_report([f], apk_sha256="c" * 64)
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        basis = "AS-0009|com.x/.P||"
        expected = hashlib.sha256(basis.encode()).hexdigest()[:16]
        self.assertEqual(f["finding_id"], expected)

    def test_flow_discriminators_prevent_id_collision(self):
        cases = (("sink", "Lx/A;->a()V", "Lx/B;->b()V"),
                 ("src_line", 10, 11),
                 ("file_offset", 0x100, 0x200))
        for key, v1, v2 in cases:
            a = make_finding(file="f.smali", kind="reachability",
                             detail={"sink": "Lx/S;->s()V", key: v1})
            b = make_finding(file="f.smali", kind="reachability",
                             detail={"sink": "Lx/S;->s()V", key: v2})
            r = make_report([a, b])
            EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
            self.assertNotEqual(a["finding_id"], b["finding_id"], key)
            self.assertFalse(b["finding_id"].endswith("-2"), key)


class TestEvidenceItems(unittest.TestCase):
    def test_observation_vs_interpretation(self):
        f = make_finding()
        r = make_report([f])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        item = f["evidence_items"][0]
        self.assertEqual(item["observation"], "android:exported=true")
        self.assertEqual(item["interpretation"], "Exported provider")
        self.assertEqual(item["excerpt_sha256"],
                         hashlib.sha256(b"android:exported=true").hexdigest())
        self.assertEqual(item["type"], "manifest_attribute")
        self.assertEqual(item["confidence"], "candidate")

    def test_native_detail_reused(self):
        f = make_finding(
            title="Native secret candidate", kind="regex", file="lib/x86_64/libx.so",
            detail={"file_offset": 4096, "encoding": "ascii",
                    "source_artifact_sha256": "b" * 64,
                    "classification": "candidate-string",
                    "confidence": "candidate", "validation": "not_runtime_verified"})
        r = make_report([f])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        item = f["evidence_items"][0]
        self.assertEqual(item["type"], "native_bytes")
        self.assertEqual(item["artifact_sha256"], "b" * 64)
        self.assertEqual(item["location"]["elf_file_offset"], 4096)

    def test_smali_line_location(self):
        f = make_finding(kind="smali-taint", file="a/b.smali",
                         component="", detail={"line": 42})
        r = make_report([f])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        item = f["evidence_items"][0]
        self.assertEqual(item["type"], "smali_call")
        self.assertEqual(item["location"]["line_start"], 42)
        self.assertEqual(item["location"]["line_end"], 42)

    def test_confidence_mapping(self):
        self.assertEqual(EV.map_confidence("confirmed_symbol_match"), "supported")
        self.assertEqual(EV.map_confidence("supported_registration_match"), "supported")
        self.assertEqual(EV.map_confidence("candidate_string_or_table_match"), "candidate")
        self.assertEqual(EV.map_confidence("unresolved"), "inconclusive")
        self.assertEqual(EV.map_confidence("verified"), "verified")
        self.assertEqual(EV.map_confidence("no-such-label"), "candidate")
        self.assertEqual(EV.map_confidence(None), "candidate")

    def test_observation_redacted_legacy_untouched(self):
        raw = "key=AKIAIOSFODNN7EXAMPLE"
        f = make_finding(evidence=raw)
        r = make_report([f])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        item = f["evidence_items"][0]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", item["observation"])
        self.assertIn("[redacted:", item["observation"])
        self.assertEqual(f["evidence"], raw)

    def test_limitations_from_detail_and_status(self):
        f = make_finding(detail={
            "truncated": True,
            "parse_coverage": {"methods": 9, "calls": 30,
                               "malformed_methods": 2}})
        r = make_report([f], analysis={"status": "partial"})
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        text = " | ".join(f["evidence_items"][0]["limitations"])
        self.assertIn("truncated", text)
        self.assertIn("malformed", text)
        self.assertIn("static-only", text)
        self.assertIn("partial", text)

    def test_limitations_ignore_informational_coverage_counts(self):
        f = make_finding(detail={"parse_coverage": {
            "methods": 120, "calls": 400, "calls_legacy_fallback": 0,
            "unparsed_invokes": 0, "malformed_methods": 0}})
        r = make_report([f])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        text = " | ".join(f["evidence_items"][0]["limitations"])
        self.assertNotIn("parser coverage incomplete", text)

    def test_limitations_count_only_problem_counters(self):
        f = make_finding(detail={"parse_coverage": {
            "methods": 120, "calls": 400, "calls_legacy_fallback": 1,
            "unparsed_invokes": 2, "malformed_methods": 0}})
        r = make_report([f])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        text = " | ".join(f["evidence_items"][0]["limitations"])
        self.assertIn("parser coverage incomplete (3", text)

    def test_attach_idempotent(self):
        f = make_finding()
        r = make_report([f])
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        once = json.dumps({"id": f["finding_id"], "items": f["evidence_items"]},
                          sort_keys=True)
        EV.attach_report_metadata(r, started_at="T2", completed_at="T3")
        twice = json.dumps({"id": f["finding_id"], "items": f["evidence_items"]},
                           sort_keys=True)
        self.assertEqual(once, twice)


class TestLegacyPreserved(unittest.TestCase):
    def test_top_level_and_finding_fields_unchanged(self):
        f = make_finding()
        r = make_report([f])
        before_top = {k: v for k, v in r.items() if k != "findings"}
        before_f = copy.deepcopy(f)
        EV.attach_report_metadata(r, started_at="T0", completed_at="T1")
        for k, v in before_top.items():
            self.assertEqual(r[k], v, f"top-level {k} changed")
        for k, v in before_f.items():
            self.assertEqual(f[k], v, f"finding field {k} changed")
        self.assertIn("finding_id", f)
        self.assertIn("evidence_items", f)
        self.assertEqual(r["analysis"], before_top["analysis"])


if __name__ == "__main__":
    unittest.main()
