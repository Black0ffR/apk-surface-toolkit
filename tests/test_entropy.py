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
