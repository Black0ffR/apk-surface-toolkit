"""RT-01 tests: normalize runtime JSONL observations and correlate to static ids.

Covers plan §17.4: correct mapping with known load bias, hash mismatch,
missing load-bias data, duplicate/out-of-order events, unresolved runtime
addresses, and "not observed" never being reported as "unreachable".
Parsing only — no instrumentation is executed, and inputs are bounded.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest

from triagekit.elf import LoadSegment
from triagekit import runtime_trace as RT

SEGMENTS = [
    LoadSegment(file_offset=0x0, virtual_address=0x0, file_size=0x1000,
                memory_size=0x1000, flags=5, alignment=0x1000),
    LoadSegment(file_offset=0x1000, virtual_address=0x2000, file_size=0x800,
                memory_size=0x900, flags=6, alignment=0x1000),
]
LIB = {"name": "libx.so", "sha256": "b" * 64, "abi": "arm64-v8a",
       "segments": SEGMENTS, "load_bias": 0x1000}


def ev(**kw) -> dict:
    base = {
        "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
        "process": {"package": "com.x", "pid": 42},
        "artifact_sha256": "a" * 64,
        "layer": "native", "static_identity": None,
        "runtime_identity": "0x3100", "address_kind": "runtime-address",
        "mapping_status": "unresolved", "source": "unit-test",
    }
    base.update(kw)
    return base


def lines(*objs) -> list[str]:
    return [json.dumps(o) for o in objs]


class TestParseTrace(unittest.TestCase):
    def test_valid_events_normalized(self):
        events, problems = RT.parse_trace(lines(ev()))
        self.assertEqual(problems, [])
        e = events[0]
        self.assertEqual(e["event_id"], "e1")
        self.assertEqual(e["static_identity"], None)
        self.assertEqual(e["mapping_status"], "unresolved")
        self.assertEqual(len(e["raw_event_sha256"]), 64)
        self.assertFalse(e.get("out_of_order", False))

    def test_malformed_json_is_a_problem_not_a_crash(self):
        events, problems = RT.parse_trace(['{"a": 1', json.dumps(ev())])
        self.assertEqual(len(events), 1)
        self.assertEqual(problems[0]["problem"], "malformed-json")
        self.assertEqual(problems[0]["line"], 1)
        self.assertEqual(len(problems[0]["line_sha256"]), 64)

    def test_non_object_line_rejected(self):
        events, problems = RT.parse_trace(["[1,2,3]"])
        self.assertEqual(events, [])
        self.assertEqual(problems[0]["problem"], "not-object")

    def test_blank_lines_skipped_silently(self):
        events, problems = RT.parse_trace(["", "   ", json.dumps(ev())])
        self.assertEqual(len(events), 1)
        self.assertEqual(problems, [])

    def test_event_cap_is_explicit_not_silent(self):
        events, problems = RT.parse_trace(lines(ev(event_id="a"), ev(event_id="b"),
                                                ev(event_id="c")), max_events=2)
        self.assertEqual(len(events), 2)
        self.assertEqual([p["problem"] for p in problems], ["event-cap-reached"])

    def test_line_too_long_is_bounded(self):
        long_line = json.dumps(ev(blob="x" * 100))
        events, problems = RT.parse_trace([long_line], max_line_bytes=64)
        self.assertEqual(events, [])
        self.assertEqual(problems[0]["problem"], "line-too-long")

    def test_duplicate_event_recorded_once(self):
        raw = ev()
        events, problems = RT.parse_trace(lines(raw, raw))
        self.assertEqual(len(events), 1)
        self.assertEqual(problems[0]["problem"], "duplicate-event")

    def test_out_of_order_flagged_but_kept(self):
        a = ev(event_id="a", timestamp="2026-01-01T00:00:02Z")
        b = ev(event_id="b", timestamp="2026-01-01T00:00:01Z")
        events, problems = RT.parse_trace(lines(a, b))
        self.assertEqual([e["event_id"] for e in events], ["a", "b"])
        self.assertFalse(events[0]["out_of_order"])
        self.assertTrue(events[1]["out_of_order"])
        self.assertEqual(problems, [])

    def test_missing_event_id_gets_deterministic_id(self):
        raw = ev()
        raw.pop("event_id")
        r1, _ = RT.parse_trace(lines(raw))
        r2, _ = RT.parse_trace(lines(raw))
        self.assertTrue(r1[0]["event_id"])
        self.assertEqual(r1[0]["event_id"], r2[0]["event_id"])


class TestArtifactValidation(unittest.TestCase):
    def test_matching_apk_hash_passes(self):
        events, _ = RT.parse_trace(lines(ev(layer="java", runtime_identity="com.x.Y.z")))
        problems = RT.check_artifacts(events, apk_sha256="a" * 64)
        self.assertEqual(problems, [])
        self.assertTrue(events[0]["artifact_match"])

    def test_mismatched_apk_hash_flagged(self):
        events, _ = RT.parse_trace(lines(ev(layer="java", runtime_identity="com.x.Y.z")))
        problems = RT.check_artifacts(events, apk_sha256="f" * 64)
        self.assertEqual(problems[0]["problem"], "artifact-hash-mismatch")
        self.assertFalse(events[0]["artifact_match"])

    def test_library_hash_checked_when_expected(self):
        events, _ = RT.parse_trace(lines(ev(library="libx.so",
                                            library_sha256="d" * 64)))
        problems = RT.check_artifacts(
            events, apk_sha256="a" * 64,
            libraries={"libx.so": "c" * 64})
        kinds = [p["problem"] for p in problems]
        self.assertIn("library-hash-mismatch", kinds)


class TestNativeMapping(unittest.TestCase):
    def _events(self, runtime_identity):
        events, problems = RT.parse_trace(
            lines(ev(runtime_identity=runtime_identity, library="libx.so")))
        self.assertEqual(problems, [])
        return events

    def test_mapping_with_known_load_bias(self):
        events = self._events("0x3100")          # va 0x2100 with bias 0x1000
        RT.map_native_events(events, libraries=[LIB])
        e = events[0]
        self.assertEqual(e["mapping_status"], "static-file-mapping")
        loc = e["location"]
        self.assertEqual(loc["file_offset"], 0x1100)
        self.assertEqual(loc["elf_virtual_address"], 0x2100)
        self.assertEqual(loc["runtime_address"], 0x3100)
        self.assertEqual(loc["load_bias"], 0x1000)
        self.assertEqual(e["static_identity"], "elf:libx.so:0x2100")

    def test_bss_only_address_is_memory_only(self):
        events = self._events("0x3850")          # va 0x2850 -> bss
        RT.map_native_events(events, libraries=[LIB])
        e = events[0]
        self.assertEqual(e["mapping_status"], "memory-only")
        self.assertIsNone(e["location"]["file_offset"])
        self.assertEqual(e["location"]["elf_virtual_address"], 0x2850)

    def test_unmapped_address_stays_unresolved(self):
        events = self._events("0x105000")
        RT.map_native_events(events, libraries=[LIB])
        e = events[0]
        self.assertEqual(e["mapping_status"], "unmapped")
        self.assertIsNone(e["static_identity"])
        self.assertIsNone(e["location"]["elf_virtual_address"])

    def test_missing_load_bias_is_unresolved(self):
        lib = dict(LIB, load_bias=None)
        events = self._events("0x3100")
        RT.map_native_events(events, libraries=[lib])
        e = events[0]
        self.assertEqual(e["mapping_status"], "unresolved")
        self.assertIsNone(e["static_identity"])
        self.assertIn("load bias", "; ".join(e["limitations"]))

    def test_unknown_library_is_unresolved(self):
        events = self._events("0x3100")
        RT.map_native_events(events, libraries=[])
        e = events[0]
        self.assertEqual(e["mapping_status"], "unresolved")
        self.assertIn("library", "; ".join(e["limitations"]).lower())

    def test_non_address_identity_is_unresolved(self):
        events = self._events("JNI_OnLoad")
        RT.map_native_events(events, libraries=[LIB])
        self.assertEqual(events[0]["mapping_status"], "unresolved")

    def test_runtime_address_never_assumed_equal_to_va(self):
        events = self._events("0x3100")          # runtime address, not the VA
        RT.map_native_events(events, libraries=[LIB])
        loc = events[0]["location"]
        self.assertEqual(loc["runtime_address"], 0x3100)
        self.assertEqual(loc["elf_virtual_address"], 0x2100)
        self.assertNotEqual(loc["runtime_address"], loc["elf_virtual_address"])


class TestCorrelation(unittest.TestCase):
    def test_java_exact_match_confirmed(self):
        events, _ = RT.parse_trace(lines(ev(layer="java", runtime_identity="com.x.Y.z",
                                             artifact_sha256="a" * 64)))
        out = RT.correlate(events, apk_sha256="a" * 64,
                           static_identities={"com.x.Y.z"})
        e = out["events"][0]
        self.assertEqual(e["static_identity"], "com.x.Y.z")
        self.assertEqual(e["static_mapping"]["kind"], "confirmed")
        self.assertEqual(e["static_mapping"]["method"], "exact-static-identity-match")
        self.assertEqual(out["unresolved"], [])

    def test_java_unknown_identity_unresolved(self):
        events, _ = RT.parse_trace(lines(ev(layer="java", runtime_identity="com.x.Nope")))
        out = RT.correlate(events, apk_sha256="a" * 64,
                           static_identities={"com.x.Y.z"})
        e = out["events"][0]
        self.assertIsNone(e["static_identity"])
        self.assertEqual(e["static_mapping"]["kind"], "unresolved")
        self.assertEqual(len(out["unresolved"]), 1)

    def test_artifact_mismatch_blocks_mapping(self):
        events, _ = RT.parse_trace(lines(ev(runtime_identity="0x3100",
                                             library="libx.so",
                                             artifact_sha256="f" * 64)))
        out = RT.correlate(events, apk_sha256="a" * 64, libraries=[LIB])
        e = out["events"][0]
        self.assertFalse(e["artifact_match"])
        self.assertEqual(e["mapping_status"], "unresolved")
        self.assertIsNone(e["static_identity"])
        self.assertEqual(out["artifact_problems"][0]["problem"], "artifact-hash-mismatch")

    def test_not_observed_is_not_unreachable(self):
        out = RT.correlate([], apk_sha256="a" * 64,
                           static_identities={"jni:com.x.Y.z", "jni:com.x.Q.w"})
        self.assertEqual(out["not_observed"], ["jni:com.x.Q.w", "jni:com.x.Y.z"])
        blob = json.dumps(out)
        self.assertNotIn("unreachable", blob)
        self.assertTrue(any("not observed" in x for x in out["limitations"]))

    def test_summary_counts_and_duplicates(self):
        a = ev(event_id="a", layer="java", runtime_identity="com.x.Y.z")
        b = ev(event_id="b", layer="native", runtime_identity="0x3100", library="libx.so")
        events, problems = RT.parse_trace(lines(a, b, dict(a)))
        out = RT.correlate(events, apk_sha256="a" * 64, libraries=[LIB],
                           static_identities={"com.x.Y.z"}, problems=problems)
        self.assertEqual(out["summary"]["events_observed"], 2)
        self.assertEqual(out["summary"]["duplicates"], 1)
        self.assertEqual(out["summary"]["confirmed"], 2)
        self.assertEqual(out["summary"]["by_layer"]["native"], 1)

    def test_out_of_order_survives_correlation(self):
        a = ev(event_id="a", timestamp="2026-01-01T00:00:02Z")
        b = ev(event_id="b", timestamp="2026-01-01T00:00:01Z")
        events, _ = RT.parse_trace(lines(a, b))
        out = RT.correlate(events, apk_sha256="a" * 64, libraries=[LIB])
        self.assertEqual(out["summary"]["out_of_order"], 1)
        self.assertEqual(len(out["events"]), 2)


class TestJniSymbolErrorsForwarded(unittest.TestCase):
    """F12: library record symbol_errors reach JNI correlation."""

    SMALI = (".class public Lcom/example/Foo;\n"
             ".super Ljava/lang/Object;\n"
             ".method public static native transform([B)[B\n"
             ".end method\n")

    def test_tree_correlation_uses_symbol_errors(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "smali", "com", "example"))
            with open(os.path.join(td, "smali", "com", "example", "Foo.smali"),
                      "w", encoding="utf-8") as f:
                f.write(self.SMALI)
            recs = RT.jni_records_from_tree(td, [
                {"name": "libfoo.so", "sha256": "0" * 64, "symbols": [],
                 "symbol_errors": ["truncated dynstr"]}])
        self.assertTrue(recs)
        joined = " ".join(recs[0]["limitations"]).lower()
        self.assertIn("unparseable", joined)


if __name__ == "__main__":
    unittest.main()
