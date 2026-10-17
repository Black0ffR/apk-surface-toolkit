"""Batch I: runtime-trace CLI/report integration (RT-01 continued).

Ingest normalized JSONL traces from the CLI, validate artifact
compatibility, correlate only established identities (ELF translation
with an explicit load bias; JNI symbol matches of confirmed/supported
confidence), emit ``runtime_event`` evidence items distinct from static
findings, and keep runtime evidence additive. No APK or native code is
executed and no network is contacted; all artifacts are synthetic.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile

from triagekit import cli
from triagekit import report as RPT
from triagekit import runtime_trace as RT
from tests.test_elf import _build

MAIN_REL = "smali/com/example/app/MainActivity.smali"
MAIN_SIG = ("Lcom/example/app/MainActivity;->"
            "onCreate(Landroid/os/Bundle;)V")
SO_ENTRY = "lib/x86_64/libx.so"

MAIN_SMALI = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 1
    return-void
.end method
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _make_apk(tmp: str) -> tuple[str, bytes]:
    so_bytes = _build([(0x0, 0x0, 0x400, 0x400)])
    apk = os.path.join(tmp, "sample.apk")
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr(SO_ENTRY, so_bytes)
    return apk, so_bytes


def _make_decoded(tmp: str) -> str:
    decoded = os.path.join(tmp, "decoded")
    _write(os.path.join(decoded, *MAIN_REL.split("/")), MAIN_SMALI)
    return decoded


def _make_analysis(tmp: str, apk: str, decoded: str, apk_sha: str) -> str:
    report = {
        "tool": "apk-surface", "version": "0.2.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "apk_path": apk, "apk_sha256": apk_sha, "size": 1234,
        "workspace": tmp,
        "decode": {"ok": True, "dir": decoded, "manifest_only": False},
        "structure": {"so_files": [SO_ENTRY], "abis": ["x86_64"]},
        "analysis": {"status": "complete", "stages": [], "limitations": []},
        "findings": [{"id": "AS-0099", "rule": "AS-0099", "title": "T",
                      "severity": "medium", "kind": "manifest",
                      "component": "com.x/.A", "file": "",
                      "evidence": "android:exported=true",
                      "recommendation": "x", "static_only": True}],
        "severity_counts": {"medium": 1},
    }
    path = os.path.join(tmp, "analysis.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f)
    return path


def _ev(**kw) -> dict:
    base = {
        "event_id": kw.pop("event_id", "e1"),
        "timestamp": kw.pop("timestamp", "2026-01-01T00:00:00Z"),
        "process": {"package": "com.example", "pid": 42},
        "artifact_sha256": kw.pop("artifact_sha256", ""),
        "layer": kw.pop("layer", "java"),
        "static_identity": None,
        "runtime_identity": kw.pop("runtime_identity", MAIN_SIG),
        "address_kind": None,
        "mapping_status": "unresolved",
        "source": "unit-test",
    }
    base.update(kw)
    return base


def _run_cli(args) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.main(list(args))
    return rc, buf.getvalue()


class TraceTreeCase(unittest.TestCase):
    """Shared synthetic APK + decoded tree + analysis.json."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        tmp = self._td.name
        self.apk, self.so_bytes = _make_apk(tmp)
        self.apk_sha = _sha256(open(self.apk, "rb").read())
        self.so_sha = _sha256(self.so_bytes)
        self.decoded = _make_decoded(tmp)
        self.analysis = _make_analysis(tmp, self.apk, self.decoded, self.apk_sha)
        self.trace = os.path.join(tmp, "trace.jsonl")
        self.tmp = tmp

    def _write_trace(self, objs) -> str:
        _write(self.trace, "\n".join(json.dumps(o) for o in objs) + "\n")
        return self.trace

    def _load_analysis(self) -> dict:
        with open(self.analysis, encoding="utf-8") as f:
            return json.load(f)


class TestTraceCli(TraceTreeCase):
    def test_cli_ingests_normalizes_and_correlates(self):
        self._write_trace([
            _ev(artifact_sha256=self.apk_sha),
            _ev(event_id="e2", timestamp="2026-01-01T00:00:01Z",
                artifact_sha256=self.apk_sha, layer="native",
                runtime_identity="0x1010", library="libx.so",
                library_sha256=self.so_sha, load_bias=0x1000),
        ])
        rc, out = _run_cli(["trace", self.trace, "-a", self.analysis,
                            "--json"])
        self.assertEqual(rc, 0)
        block = json.loads(out)
        self.assertEqual(block["trace"]["source"], "trace.jsonl")
        self.assertEqual(block["trace"]["artifact_sha256"], self.apk_sha)
        self.assertEqual(block["summary"]["events_observed"], 2)
        self.assertEqual(block["summary"]["confirmed"], 2)
        self.assertEqual(block["summary"]["unresolved"], 0)
        self.assertEqual(len(block["evidence_items"]), 2)
        item = block["evidence_items"][0]
        self.assertEqual(item["type"], "runtime_event")
        self.assertEqual(item["confidence"], "observed")
        self.assertEqual(item["producer"], "triagekit:runtime_trace")
        self.assertNotEqual(item["observation"], item["interpretation"])

        updated = self._load_analysis()
        self.assertIn("runtime_trace", updated)
        self.assertEqual(updated["runtime_trace"]["summary"]["confirmed"], 2)
        self.assertTrue(os.path.exists(os.path.join(self.tmp,
                                                    "runtime_trace.json")))
        events = updated["runtime_trace"]["events"]
        java = [e for e in events if e["layer"] == "java"][0]
        native = [e for e in events if e["layer"] == "native"][0]
        self.assertEqual(java["static_identity"], MAIN_SIG)
        self.assertEqual(java["static_mapping"]["kind"], "confirmed")
        self.assertEqual(native["static_identity"], "elf:libx.so:0x10")
        self.assertEqual(native["mapping_status"], "static-file-mapping")
        self.assertEqual(native["location"]["runtime_address"], 0x1010)
        self.assertEqual(native["location"]["elf_virtual_address"], 0x10)

    def test_cli_artifact_mismatch_blocks_mapping(self):
        self._write_trace([
            _ev(artifact_sha256="f" * 64),
        ])
        rc, out = _run_cli(["trace", self.trace, "-a", self.analysis,
                            "--json"])
        self.assertEqual(rc, 0)
        block = json.loads(out)
        self.assertEqual(block["summary"]["confirmed"], 0)
        self.assertEqual(block["summary"]["unresolved"], 1)
        self.assertTrue(block["artifact_problems"])
        self.assertEqual(block["artifact_problems"][0]["problem"],
                         "artifact-hash-mismatch")
        self.assertFalse(block["events"][0]["artifact_match"])
        self.assertIn("unresolved", block["evidence_items"][0]["interpretation"])

    def test_cli_accounts_for_malformed_duplicate_out_of_order(self):
        good = _ev(event_id="a", timestamp="2026-01-01T00:00:02Z",
                   artifact_sha256=self.apk_sha)
        late = _ev(event_id="b", timestamp="2026-01-01T00:00:01Z",
                   artifact_sha256=self.apk_sha)
        _write(self.trace, "\n".join([
            '{"event_id": "broken"',
            json.dumps(good),
            json.dumps(dict(good)),
            json.dumps(late),
        ]) + "\n")
        rc, out = _run_cli(["trace", self.trace, "-a", self.analysis,
                            "--json"])
        self.assertEqual(rc, 0)
        block = json.loads(out)
        self.assertEqual(block["summary"]["events_observed"], 2)
        self.assertEqual(block["summary"]["duplicates"], 1)
        self.assertEqual(block["summary"]["parse_problems"], 1)
        self.assertEqual(block["summary"]["out_of_order"], 1)
        self.assertTrue(any(p["problem"] == "malformed-json"
                            for p in block["parse_problems"]))
        self.assertTrue(any(p["problem"] == "duplicate-event"
                            for p in block["parse_problems"]))

    def test_cli_is_additive_findings_and_status_unchanged(self):
        before = self._load_analysis()
        findings_before = copy.deepcopy(before["findings"])
        counts_before = copy.deepcopy(before["severity_counts"])
        status_before = copy.deepcopy(before["analysis"])
        self._write_trace([_ev(artifact_sha256=self.apk_sha)])
        rc, _ = _run_cli(["trace", self.trace, "-a", self.analysis])
        self.assertEqual(rc, 0)
        after = self._load_analysis()
        self.assertEqual(after["findings"], findings_before)
        self.assertEqual(after["severity_counts"], counts_before)
        self.assertEqual(after["analysis"], status_before)

    def test_cli_missing_inputs_return_rc2(self):
        rc, _ = _run_cli(["trace", os.path.join(self.tmp, "nope.jsonl"),
                          "-a", self.analysis])
        self.assertEqual(rc, 2)
        self._write_trace([_ev()])
        rc, _ = _run_cli(["trace", self.trace, "-a",
                          os.path.join(self.tmp, "nope.json")])
        self.assertEqual(rc, 2)

    def test_cli_rerenders_report_md_with_runtime_section(self):
        _write(os.path.join(self.tmp, "report.md"), "# old report\n")
        self._write_trace([_ev(artifact_sha256=self.apk_sha)])
        rc, _ = _run_cli(["trace", self.trace, "-a", self.analysis])
        self.assertEqual(rc, 0)
        with open(os.path.join(self.tmp, "report.md"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("Runtime trace", text)
        self.assertIn("not evidence of unreachability", text)


class TestRuntimeIntegrationUnits(unittest.TestCase):
    def test_load_trace_reads_file_and_reports_problems(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "t.jsonl")
            _write(path, '{"event_id": "x"}\nnot-json\n')
            events, problems = RT.load_trace(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_id"], "x")
            self.assertEqual(problems[0]["problem"], "malformed-json")
            self.assertEqual(events[0]["source"],
                             os.path.basename(path))
            missing, miss_problems = RT.load_trace(os.path.join(td, "no.jsonl"))
            self.assertEqual(missing, [])
            self.assertEqual(miss_problems[0]["problem"], "trace-unreadable")

    def test_apply_event_load_biases_records_only_observed_bias(self):
        events, problems = RT.parse_trace([
            json.dumps(_ev(event_id="n1", layer="native",
                           runtime_identity="0x1010", library="libx.so",
                           load_bias=0x1000)),
            json.dumps(_ev(event_id="n2", timestamp="2026-01-01T00:00:01Z",
                           layer="native", runtime_identity="0x1020",
                           library="libx.so")),
        ])
        self.assertEqual(problems, [])
        libs = [{"name": "libx.so", "sha256": "b" * 64, "abi": "x86_64",
                 "segments": []}]
        self.assertEqual(RT.apply_event_load_biases(events, libs), 1)
        self.assertEqual(libs[0]["load_bias"], 0x1000)
        self.assertEqual(RT.apply_event_load_biases(events, libs), 0)

    def test_library_records_from_apk(self):
        with tempfile.TemporaryDirectory() as td:
            apk, so_bytes = _make_apk(td)
            records, problems = RT.library_records_from_apk(
                apk, [SO_ENTRY])
            self.assertEqual(problems, [])
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec["name"], "libx.so")
            self.assertEqual(rec["sha256"], _sha256(so_bytes))
            self.assertEqual(rec["abi"], "aarch64")
            self.assertEqual(len(rec["segments"]), 1)
            self.assertIsNone(rec.get("load_bias"))

    def test_library_records_from_apk_errors_are_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            records, problems = RT.library_records_from_apk(
                os.path.join(td, "nope.apk"), [SO_ENTRY])
            self.assertEqual(records, [])
            self.assertEqual(problems[0]["problem"], "apk-unreadable")
            apk, _ = _make_apk(td)
            with zipfile.ZipFile(apk, "a") as z:
                z.writestr("lib/x86_64/libbad.so", b"not an elf")
            records, problems = RT.library_records_from_apk(
                apk, ["lib/x86_64/libbad.so"])
            self.assertEqual(records, [])
            self.assertEqual(problems[0]["problem"], "elf-parse-failed")

    def test_jni_records_from_tree_confirmed_symbol(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = os.path.join(td, "decoded")
            _write(os.path.join(decoded, "smali", "com", "example",
                                "Foo.smali"),
                   ".class public Lcom/example/Foo;\n"
                   ".method public static native transform([B)[B\n"
                   ".end method\n")
            libs = [{
                "name": "libx.so", "sha256": "b" * 64, "abi": "aarch64",
                "segments": [],
                "symbols": [{"name": "Java_com_example_Foo_transform",
                             "value": 0x2200, "size": 32, "type": "func",
                             "bind": "global", "shndx": 2, "defined": True}],
            }]
            records = RT.jni_records_from_tree(decoded, libs)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["java_method"],
                             "Lcom/example/Foo;->transform([B)[B")
            self.assertEqual(records[0]["confidence"],
                             "confirmed_symbol_match")
            self.assertEqual(records[0]["native_symbol"],
                             "Java_com_example_Foo_transform")

    def test_link_jni_only_links_established_identities(self):
        events, _ = RT.parse_trace([
            json.dumps(_ev(event_id="n1", layer="native",
                           runtime_identity="0x1010", library="libx.so")),
        ])
        events[0]["location"] = {"elf_virtual_address": 0x2200}
        jni_records = [
            {"java_method": "Lcom/example/Foo;->transform([B)[B",
             "native_library": "libx.so", "library_sha256": "b" * 64,
             "mapping_type": "conventional-symbol",
             "native_symbol": "Java_com_example_Foo_transform",
             "elf_virtual_address": 0x2200,
             "confidence": "confirmed_symbol_match"},
            {"java_method": "Lcom/example/Foo;->other()V",
             "native_library": "libx.so", "library_sha256": "b" * 64,
             "mapping_type": "dynamic-registration-candidate",
             "native_symbol": "f_other", "elf_virtual_address": 0x2300,
             "confidence": "candidate_string_or_table_match"},
        ]
        self.assertEqual(RT.link_jni(events, jni_records), 1)
        self.assertEqual(events[0]["jni_mapping"]["java_method"],
                         "Lcom/example/Foo;->transform([B)[B")
        self.assertEqual(RT.link_jni(events, jni_records[:1]), 1)

    def test_build_evidence_items_provenance_and_bound(self):
        events, problems = RT.parse_trace([
            json.dumps(_ev(event_id="j1", artifact_sha256="a" * 64)),
            json.dumps(_ev(event_id="n1", layer="native",
                           artifact_sha256="a" * 64,
                           runtime_identity="0x1010", library="libx.so")),
        ])
        events[0]["static_identity"] = MAIN_SIG
        events[0]["static_mapping"] = {"kind": "confirmed",
                                       "method": "exact-static-identity-match"}
        events[1]["static_mapping"] = {"kind": "unresolved", "method": None}
        items, truncated = RT.build_evidence_items(
            events, artifact_sha256="a" * 64)
        self.assertEqual(len(items), 2)
        self.assertFalse(truncated)
        for item in items:
            self.assertEqual(item["type"], "runtime_event")
            self.assertEqual(item["confidence"], "observed")
            self.assertEqual(item["producer"], "triagekit:runtime_trace")
            self.assertEqual(len(item["excerpt_sha256"]), 64)
            self.assertEqual(item["artifact_sha256"], "a" * 64)
        self.assertIn(MAIN_SIG, items[0]["observation"])
        self.assertIn(MAIN_SIG, items[0]["interpretation"])
        self.assertIn("unresolved", items[1]["interpretation"])
        self.assertTrue(items[1]["limitations"])
        bounded, trunc = RT.build_evidence_items(
            events, artifact_sha256="a" * 64, max_items=1)
        self.assertEqual(len(bounded), 1)
        self.assertTrue(trunc)

    def test_report_renders_runtime_section_only_when_present(self):
        report = {
            "tool": "apk-surface", "version": "0.2.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "apk_path": "/tmp/a.apk", "apk_sha256": "a" * 64, "size": 1,
            "workspace": "/tmp/ws", "package": "com.example",
            "version_name": "1.0", "min_sdk": "24", "target_sdk": "34",
            "analysis": {"status": "complete", "stages": [],
                         "limitations": []},
            "findings": [], "severity_counts": {},
        }
        text = RPT.render(report)
        self.assertNotIn("Runtime trace", text)
        report["runtime_trace"] = {
            "trace": {"source": "trace.jsonl", "artifact_sha256": "a" * 64},
            "summary": {"events_observed": 2, "confirmed": 1,
                        "unresolved": 1, "duplicates": 0,
                        "out_of_order": 0},
            "not_observed": ["Lcom/example/Foo;->bar()V"],
            "unresolved": [], "artifact_problems": [],
            "parse_problems": [], "jni_links": [],
            "evidence_items": [],
            "limitations": list(RT.TRACE_LIMITATIONS),
        }
        text = RPT.render(report)
        self.assertIn("Runtime trace", text)
        self.assertIn("not evidence of unreachability", text)
        self.assertIn("Lcom/example/Foo;->bar()V", text)


if __name__ == "__main__":
    unittest.main()
