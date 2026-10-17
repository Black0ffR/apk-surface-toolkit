"""Batch I: decoded-tree end-to-end pipeline regression.

Runs the real analyzer orchestration from a decoded tree to the written
report: manifest + regex + interprocedural smali-taint + call-graph
reachability, stage accounting, evidence/provenance attachment, and the
CLI command metadata. External tools (apktool/apksigner/aapt2/apkid) are
absent by design; only the decoder is stubbed to hand over a decoded
tree, so this is a decoded-tree test, not an APK-decode test. Nothing is
executed and no network is contacted.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from unittest import mock

from triagekit import analyzer as AN
from triagekit import cli

MANIFEST = """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application android:label="E2E">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:scheme="demo"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

MAIN_SMALI = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
    const-string v0, "SECRET_MARKER"
    invoke-virtual {p0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Helper;->identity(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

HELPER_SMALI = """\
.class public Lcom/example/app/Helper;
.super Ljava/lang/Object;

.method public static identity(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    move-object v0, p0
    return-object v0
.end method
"""

RULES = {
    "AS-9001-exported.json": {
        "id": "AS-9001", "title": "Exported component with no permission",
        "kind": "manifest", "check": "unprotected_exported",
        "severity": "high", "recommendation": "restrict",
    },
    "AS-9002-marker.json": {
        "id": "AS-9002", "title": "Marker string present",
        "kind": "regex", "check": "regex", "severity": "medium",
        "recommendation": "x",
        "params": {"root": ".", "pattern": "SECRET_MARKER",
                   "exts": [".smali"]},
    },
    "AS-9003-taint.json": {
        "id": "AS-9003", "title": "Input reaches WebView",
        "kind": "smali-taint", "check": "smali_taint", "severity": "high",
        "recommendation": "x",
        "params": {
            "sources": [{"name": "getStringExtra", "match": "name"}],
            "sinks": [{"name": "loadUrl", "match": "name"}],
            "interprocedural": True, "cap": 15,
        },
    },
    "AS-9004-reach.json": {
        "id": "AS-9004", "title": "Exported entry reaches a sink",
        "kind": "reachability", "check": "reachability", "severity": "medium",
        "recommendation": "x",
        "params": {"sinks": ["loadUrl"], "cap": 15},
    },
}


def _sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _build_fixture(tmp: str) -> tuple[str, str, str]:
    """Returns (apk_path, decoded_dir, rules_dir)."""
    decoded = os.path.join(tmp, "decoded")
    _write(os.path.join(decoded, "AndroidManifest.xml"), MANIFEST)
    _write(os.path.join(decoded, "smali", "com", "example", "app",
                        "MainActivity.smali"), MAIN_SMALI)
    _write(os.path.join(decoded, "smali", "com", "example", "app",
                        "Helper.smali"), HELPER_SMALI)
    rules = os.path.join(tmp, "rules")
    for name, body in RULES.items():
        _write(os.path.join(rules, name), json.dumps(body, indent=2))
    _write(os.path.join(rules, "platform_permissions.txt"),
           "android.permission.INTERNET\n")
    apk = os.path.join(tmp, "sample.apk")
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr("classes.dex", b"\x00" * 128)
    return apk, decoded, rules


def _stub_decoder(decoded_src: str):
    def _decode(apk, out_dir, *, keep_res=True, timeout=600, root=None):
        shutil.copytree(decoded_src, out_dir, dirs_exist_ok=True)
        return True, "stub decode (test fixture)"
    return _decode


class TestDecodedTreeEndToEnd(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tmp = self._td.name
        self.apk, self.decoded, self.rules = _build_fixture(self.tmp)
        self.out = os.path.join(self.tmp, "out")

    def _analyse(self, command=None, out=None):
        patch = mock.patch("triagekit.apktools.decode",
                           new=_stub_decoder(self.decoded))
        patch.start()
        self.addCleanup(patch.stop)
        return AN.analyse(self.apk, out or self.out, rules_dir=self.rules,
                          command=command)

    def test_decoded_tree_cli_run_produces_report_and_evidence(self):
        patch = mock.patch("triagekit.apktools.decode",
                           new=_stub_decoder(self.decoded))
        patch.start()
        self.addCleanup(patch.stop)
        buf = io.StringIO()
        argv = ["analyze", self.apk, "-o", self.out, "--rules", self.rules,
                "--quiet"]
        with contextlib.redirect_stdout(buf):
            rc = cli.main(argv)
        self.assertEqual(rc, 1)
        ws = os.path.join(self.out, hashlib.sha256(
            open(self.apk, "rb").read()).hexdigest()[:12])
        apath = os.path.join(ws, "analysis.json")
        self.assertTrue(os.path.exists(apath))
        with open(apath, encoding="utf-8") as f:
            report = json.load(f)

        self.assertEqual(report["schema_version"], "2")
        self.assertEqual(report["run"]["command"], argv)
        self.assertEqual(report["artifact"]["sha256"], _sha256_file(self.apk))
        self.assertEqual(report["artifact"]["path_label"], "sample.apk")
        self.assertEqual(report["rule_count"], 4)
        self.assertEqual(report["rule_errors"], [])
        stages = {s["stage"]: s for s in report["analysis"]["stages"]}
        for name in ("manifest", "regex", "smali-taint", "reachability"):
            self.assertTrue(stages[name]["ran"], (name, stages[name]))
            self.assertTrue(stages[name]["complete"], (name, stages[name]))
            self.assertEqual(stages[name]["reason"], "")

        rules_found = {f["rule"] for f in report["findings"]}
        self.assertEqual(rules_found, {"AS-9001", "AS-9002", "AS-9003",
                                       "AS-9004"})
        for f in report["findings"]:
            self.assertTrue(f.get("finding_id"), f)
            items = f.get("evidence_items")
            self.assertEqual(len(items), 1, f)
            self.assertNotEqual(items[0]["observation"],
                                items[0]["interpretation"])
        taint = [f for f in report["findings"] if f["rule"] == "AS-9003"][0]
        self.assertEqual(taint["severity"], "high")
        self.assertTrue(taint["detail"]["cross_method"])
        self.assertEqual(taint["detail"]["via"],
                         ["Lcom/example/app/Helper;->identity"
                          "(Ljava/lang/String;)Ljava/lang/String;"])
        self.assertEqual(taint["detail"]["analysis"]["status"], "partial")
        self.assertIn("interprocedural summary propagation",
                      taint["detail"]["analysis"]["reason"])

        self.assertTrue(os.path.exists(os.path.join(ws, "report.md")))
        self.assertTrue(os.path.exists(os.path.join(ws, "tests.sh")))
        with open(os.path.join(ws, "report.md"), encoding="utf-8") as f:
            md = f.read()
        self.assertIn("AS-9001", md)
        self.assertIn("AS-9003", md)

    def test_decoded_tree_run_is_deterministic(self):
        first = self._analyse()
        second = self._analyse(command=["analyze", self.apk])
        ids_a = [(f["rule"], f["finding_id"]) for f in first["findings"]]
        ids_b = [(f["rule"], f["finding_id"]) for f in second["findings"]]
        self.assertEqual(ids_a, ids_b)
        self.assertEqual(first["severity_counts"], second["severity_counts"])

    def test_analyse_command_metadata_is_sanitized(self):
        report = self._analyse(command=["apk-surface", "analyze", self.apk,
                                        "--api-key", "AKIAdeadbeef1234",
                                        "--header=Authorization: Bearer x"])
        self.assertEqual(report["run"]["command"],
                         ["apk-surface", "analyze", self.apk,
                          "--api-key", "[redacted]",
                          "--header=[redacted]"])
        blob = json.dumps(report)
        self.assertNotIn("AKIAdeadbeef1234", blob)
        self.assertNotIn("Bearer x", blob)

    def test_analyse_default_command_is_empty(self):
        report = self._analyse()
        self.assertEqual(report["run"]["command"], [])

    def test_analysis_json_written_to_workspace(self):
        report = self._analyse()
        apath = os.path.join(report["workspace"], "analysis.json")
        with open(apath, encoding="utf-8") as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk["apk_sha256"], report["apk_sha256"])
        self.assertEqual(on_disk["analysis"]["status"],
                         report["analysis"]["status"])


if __name__ == "__main__":
    unittest.main()
