"""F1 regression tests: partial analysis must be visible and never clean.

Contracts under test:
- report.render() shows the analysis status, per-stage ran/complete/reason,
  and the limitations list whenever an `analysis` block is present.
- cli.human() names the partial status and every incomplete stage reason.
- cli.route() never routes a partial analysis to `complete`, and appends the
  incompleteness note to actionable routes.
- cmd_analyze exit codes: 0 = complete clean, 1 = complete with
  critical/high findings, 3 = incomplete (partial / not analysed / decode
  failed). Partial analysis must not exit 0 or 1 silently.
"""
from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from triagekit import cli as CLI
from triagekit import report as RP

PARTIAL_STAGE = {"stage": "native", "ran": True, "complete": False,
                 "reason": "5 library(ies) beyond the 20-file scan cap"}
OK_STAGE = {"stage": "manifest", "ran": True, "complete": True, "reason": ""}


def _analysis(status: str) -> dict:
    stages = [OK_STAGE]
    if status == "partial":
        stages.append(PARTIAL_STAGE)
    return {"status": status, "stages": stages,
            "limitations": ["native incomplete: 5 library(ies) beyond the 20-file scan cap"]}


def _finding(sev: str = "high") -> dict:
    return {"id": "AS-9001", "tool": "apk-surface", "rule": "AS-9001",
            "title": "t", "severity": sev, "kind": "manifest",
            "component": "", "file": "", "evidence": "e",
            "recommendation": "r", "maswe": None, "static_only": True,
            "verification": {"status": "unverified", "script": None}}


def _report(status: str, *, findings=None, ws: str = "/tmp/ws") -> dict:
    findings = findings or []
    return {
        "tool": "apk-surface", "version": "0.2.0", "generated_at": "T",
        "apk_path": "/tmp/x.apk", "apk_sha256": "a" * 64, "size": 10,
        "workspace": ws, "package": "com.x", "version_name": "1",
        "version_code": 1, "min_sdk": 1, "target_sdk": 1,
        "flags": {}, "uses_permissions": [], "defined_permissions": [],
        "components": [], "deeplinks": [], "app_links": [],
        "custom_schemes": [], "meta_data": [], "file_provider_paths": [],
        "backup_rules": [], "network_security_config": [],
        "signature": {}, "structure": {}, "packer_hints": [], "preflight": {},
        "decode": {"ok": True, "detail": "stub", "manifest_only": False,
                   "dir": None},
        "platform_permissions_known": 1, "rule_errors": [], "rule_count": 1,
        "rule_inventory": {}, "analysis": _analysis(status),
        "findings": findings, "blind_spots": [], "severity_counts": {},
    }


class TestRenderCoverageSection(unittest.TestCase):
    def test_partial_status_and_stage_reasons_are_rendered(self):
        md = RP.render(_report("partial"))
        self.assertIn("Coverage & analysis status", md)
        self.assertIn("partial", md)
        self.assertIn("native", md)
        self.assertIn("5 library(ies) beyond the 20-file scan cap", md)
        self.assertIn("inconclusive", md.lower())

    def test_complete_status_is_not_alarming(self):
        md = RP.render(_report("complete"))
        self.assertIn("complete", md)
        self.assertNotIn("inconclusive", md.lower())

    def test_report_without_analysis_block_is_unchanged(self):
        md = RP.render({"findings": []})
        self.assertNotIn("Coverage & analysis status", md)


class TestHumanCoverageOutput(unittest.TestCase):
    def test_human_reports_partial_status_and_stage_reasons(self):
        text = CLI.human(_report("partial"))
        self.assertIn("analysis: partial", text)
        self.assertIn("native", text)
        self.assertIn("5 library(ies) beyond the 20-file scan cap", text)

    def test_human_complete_has_no_analysis_warning(self):
        text = CLI.human(_report("complete"))
        self.assertNotIn("analysis: partial", text)
        self.assertNotIn("analysis: not_analysed", text)


class TestRouteCoverage(unittest.TestCase):
    def test_partial_clean_looking_report_is_not_routed_complete(self):
        kind, why = CLI.route(_report("partial"))
        self.assertNotEqual(kind, "complete")
        self.assertIn("incomplete", why.lower())

    def test_partial_with_high_findings_keeps_verify_and_notes_incomplete(self):
        r = _report("partial", findings=[_finding("high")])
        kind, why = CLI.route(r)
        self.assertEqual(kind, "verify")
        self.assertIn("incomplete", why.lower())

    def test_complete_report_is_routed_complete(self):
        kind, _why = CLI.route(_report("complete"))
        self.assertEqual(kind, "complete")

    def test_report_without_analysis_keeps_legacy_routing(self):
        r = _report("complete")
        del r["analysis"]
        kind, _why = CLI.route(r)
        self.assertEqual(kind, "complete")


class TestAnalyzeExitCodes(unittest.TestCase):
    def _run(self, report: dict) -> int:
        with tempfile.TemporaryDirectory() as td:
            apk = os.path.join(td, "sample.apk")
            with open(apk, "wb") as f:
                f.write(b"stub")
            ws = report["workspace"]
            os.makedirs(ws, exist_ok=True)
            with mock.patch("triagekit.cli.analyse", return_value=report), \
                    mock.patch("triagekit.tests_gen.generate",
                               return_value="tests.sh"):
                with contextlib.redirect_stdout(io.StringIO()):
                    return CLI.main(["analyze", apk, "-o", td, "--quiet"])

    def test_complete_clean_scan_returns_zero(self):
        with tempfile.TemporaryDirectory() as td:
            ws = os.path.join(td, "w")
            rc = self._run(_report("complete", ws=ws))
        self.assertEqual(rc, 0)

    def test_complete_with_high_finding_returns_one(self):
        with tempfile.TemporaryDirectory() as td:
            ws = os.path.join(td, "w")
            rc = self._run(_report("complete", findings=[_finding("high")],
                                   ws=ws))
        self.assertEqual(rc, 1)

    def test_partial_clean_looking_scan_returns_incomplete_not_zero(self):
        with tempfile.TemporaryDirectory() as td:
            ws = os.path.join(td, "w")
            rc = self._run(_report("partial", ws=ws))
        self.assertEqual(rc, 3)

    def test_partial_with_high_finding_returns_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            ws = os.path.join(td, "w")
            rc = self._run(_report("partial", findings=[_finding("high")],
                                   ws=ws))
        self.assertEqual(rc, 3)


class TestPartialEndToEnd(unittest.TestCase):
    """Combined F4+F1: a truncated scan cannot look like a clean negative."""

    RULE = {
        "id": "AS-9003", "title": "Input reaches WebView",
        "kind": "smali-taint", "check": "smali_taint", "severity": "high",
        "recommendation": "x",
        "params": {"sources": [{"name": "getStringExtra", "match": "name"}],
                   "sinks": [{"name": "loadUrl", "match": "name"}], "cap": 15},
    }

    def test_truncated_smali_run_is_partial_in_report_and_rc(self):
        import hashlib
        import json
        import shutil
        import zipfile
        from triagekit import analyzer as AN

        manifest = ("<manifest xmlns:android="
                    "\"http://schemas.android.com/apk/res/android\" "
                    "package=\"com.example.big\"><application/></manifest>")
        big = (
            ".class public Lcom/example/Big;\n.super Ljava/lang/Object;\n\n"
            ".method public big()V\n    .locals 2\n"
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n"
            "    move-result-object v0\n"
            "    return-void\n"
            + "".join("    # pad %06d\n" % i for i in range(40000))
            + "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V\n"
            "    return-void\n.end method\n")

        with tempfile.TemporaryDirectory() as td:
            decoded = os.path.join(td, "decoded")
            os.makedirs(os.path.join(decoded, "smali", "com", "example"))
            with open(os.path.join(decoded, "AndroidManifest.xml"), "w",
                      encoding="utf-8") as f:
                f.write(manifest)
            with open(os.path.join(decoded, "smali", "com", "example",
                                   "Big.smali"), "w", encoding="utf-8") as f:
                f.write(big)
            rules = os.path.join(td, "rules")
            os.makedirs(rules)
            with open(os.path.join(rules, "AS-9003.json"), "w",
                      encoding="utf-8") as f:
                json.dump(self.RULE, f)
            with open(os.path.join(rules, "platform_permissions.txt"), "w",
                      encoding="utf-8") as f:
                f.write("android.permission.INTERNET\n")
            apk = os.path.join(td, "sample.apk")
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("AndroidManifest.xml", b"<manifest/>")
                z.writestr("classes.dex", b"\x00" * 128)

            def _decode(_apk, out_dir, **_kw):
                shutil.copytree(decoded, out_dir, dirs_exist_ok=True)
                return True, "stub decode"

            out = os.path.join(td, "out")
            with mock.patch("triagekit.apktools.decode", new=_decode):
                report = AN.analyse(apk, out, rules_dir=rules)
                taint = next(s for s in report["analysis"]["stages"]
                             if s["stage"] == "smali-taint")
                self.assertEqual(report["findings"], [])
                self.assertFalse(taint["complete"], taint)
                self.assertIn("truncat", taint["reason"].lower())
                self.assertEqual(report["analysis"]["status"], "partial")
                md = RP.render(report)
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = CLI.main(["analyze", apk, "-o", out, "--rules", rules,
                                   "--quiet"])
        self.assertIn("Analysis status: partial", md)
        self.assertEqual(rc, 3, "partial clean-looking scan must not exit 0/1")


class TestZeroFindingsVerdictLine(unittest.TestCase):
    """C13: a zero-findings verdict must not dangle a colon and nothing else."""

    def test_zero_findings_verdict_line_has_no_dangling_colon(self):
        md = RP.render(_report("complete"))
        lines = [ln for ln in md.splitlines() if "finding(s)" in ln]
        self.assertEqual(len(lines), 1, lines)
        self.assertEqual(lines[0], "**0 finding(s)**")


if __name__ == "__main__":
    unittest.main()
