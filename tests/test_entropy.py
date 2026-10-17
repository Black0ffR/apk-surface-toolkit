"""NA-01 entropy contract tests. Synthetic fixtures only.

Contract under test: entropy.scan_region_detailed() records window
start/end/size, per-window entropy, baseline/comparison method, and flag
reasons; the numeric score stays separate from the heuristic classification.
"""
from __future__ import annotations

import random
import unittest

from triagekit import entropy as ENT


def _noise(n: int, seed: int = 4) -> bytes:
    return random.Random(seed).randbytes(n)


class TestDetailedWindows(unittest.TestCase):
    def test_window_offsets_sizes_and_entropy(self):
        data = b"\x00" * 4096 + _noise(4096) + b"\x00" * 4096
        rep = ENT.scan_region_detailed(data)
        wins = rep["windows"]
        self.assertEqual(len(wins), 3)
        self.assertEqual((wins[0]["start"], wins[0]["end"]), (0, 4096))
        self.assertEqual(wins[1]["start"], 4096)
        self.assertEqual(wins[2]["start"], 8192)
        for w in wins:
            self.assertEqual(w["end"] - w["start"], 4096)
            self.assertEqual(w["size"], 4096)
        self.assertLess(wins[0]["entropy"], 0.1)
        self.assertGreater(wins[1]["entropy"], 7.0)
        flagged = [w for w in wins if w["flagged"]]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["start"], 4096)
        self.assertTrue(flagged[0]["flag_reason"])

    def test_baseline_and_score_separate_from_classification(self):
        rep = ENT.scan_region_detailed(_noise(8192))
        self.assertIn("method", rep["baseline"])
        self.assertTrue(rep["baseline"]["method"])
        self.assertIsInstance(rep["score"], float)
        cls = rep["classification"]
        self.assertIn("value", cls)
        self.assertTrue(cls["heuristic"])
        self.assertEqual(cls["validation"], "not_runtime_verified")

    def test_classification_matches_legacy_gate(self):
        # uniform 256-symbol region hits the chi-square path deterministically
        data = bytes(range(256)) * 16
        legacy = ENT.scan_region(data)
        rep = ENT.scan_region_detailed(data)
        self.assertEqual(rep["classification"]["value"],
                         "candidate-encrypted" if legacy["encrypted"]
                         else "not-flagged")
        self.assertEqual(rep["score"], legacy["peak"])
        self.assertIn("reasons", rep)

    def test_plain_region_not_flagged(self):
        rep = ENT.scan_region_detailed(b"\x00" * 4096)
        cls = rep["classification"]
        self.assertEqual(cls["value"], "not-flagged")
        self.assertEqual(rep["windows"][0]["entropy"], 0.0)
        self.assertFalse(rep["windows"][0]["flagged"])

    def test_empty_region_explicit(self):
        rep = ENT.scan_region_detailed(b"")
        self.assertEqual(rep["windows"], [])
        self.assertEqual(rep["score"], 0.0)
        self.assertTrue(any("empty" in r.lower() for r in rep["reasons"]))

    def test_window_budget(self):
        rep = ENT.scan_region_detailed(_noise(200_000), max_windows=8)
        self.assertLessEqual(len(rep["windows"]), 8)
        self.assertEqual(rep["windows_evaluated"], len(rep["windows"]))

    def test_sustained_high_entropy_flags_region(self):
        rep = ENT.scan_region_detailed(_noise(64 * 4096))
        self.assertEqual(rep["classification"]["value"],
                         "candidate-encrypted")
        self.assertEqual(rep["state"], "sustained-high-entropy")
        self.assertTrue(rep["indicators"]["sustained"])
        self.assertGreaterEqual(rep["indicators"]["high_fraction"], 0.6)

    def test_isolated_high_entropy_window_is_not_whole_region(self):
        # Regression: one high window (embedded blob / crypto constants)
        # amid ordinary data must NOT flag the whole region as encrypted.
        data = b"\x00" * (4096 * 39) + _noise(4096)
        rep = ENT.scan_region_detailed(data)
        self.assertEqual(rep["classification"]["value"], "not-flagged")
        self.assertEqual(rep["state"], "isolated-high-entropy-region")
        self.assertTrue(rep["indicators"]["isolated"])
        self.assertLessEqual(rep["indicators"]["high_fraction"], 0.25)
        self.assertFalse(ENT.scan_region(data)["encrypted"])

    def test_ordinary_code_like_region_not_flagged(self):
        data = (bytes(range(8)) * 512) * 16
        rep = ENT.scan_region_detailed(data)
        self.assertEqual(rep["classification"]["value"], "not-flagged")
        self.assertEqual(rep["state"], "low-entropy")

    def test_classify_region_kind(self):
        self.assertEqual(ENT.classify_region_kind("classes.dex"), "dex")
        self.assertEqual(ENT.classify_region_kind("classes5.dex"), "dex")
        self.assertEqual(ENT.classify_region_kind("lib/arm64-v8a/x.so"),
                         "native")

    def test_scan_apk_tags_region_kind_and_isolated_native(self):
        import os
        import tempfile
        import zipfile
        fd, p = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("classes.dex", _noise(200_000))
                z.writestr("lib/arm64-v8a/libplain.so", b"\x00" * (4096 * 30))
                z.writestr("lib/arm64-v8a/libisolated.so",
                           b"\x00" * (4096 * 30) + _noise(4096))
            recs = ENT.scan_apk(p)
            by = {r["file"]: r for r in recs}
            self.assertEqual(by["classes.dex"]["region_kind"], "dex")
            self.assertTrue(by["classes.dex"]["encrypted"])
            self.assertTrue(by["classes.dex"]["sustained"]
                            if "sustained" in by["classes.dex"]
                            else by["classes.dex"]["encrypted"])
            iso = by["lib/arm64-v8a/libisolated.so"]
            self.assertEqual(iso["region_kind"], "native")
            self.assertFalse(iso["encrypted"])
            self.assertEqual(iso["state"], "isolated-high-entropy-region")
            self.assertNotIn("lib/arm64-v8a/libplain.so", by)
        finally:
            os.unlink(p)
