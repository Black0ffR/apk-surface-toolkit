"""B4 regression tests. Read-only; no APK execution."""
from __future__ import annotations

import glob
import os
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _readme() -> str:
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        return f.read()


class TestReadmeAccuracy(unittest.TestCase):
    def test_rule_count_matches_inventory(self):
        files = sorted(glob.glob(os.path.join(ROOT, "rules", "AS-*.json")))
        text = _readme()
        self.assertIn(str(len(files)), text)
        self.assertNotIn("19 JSON rules", text)
        self.assertNotIn("19 rules", text)

    def test_rule_kinds_documented(self):
        text = _readme().lower()
        for kind in ("manifest", "regex", "smali-taint", "reachability"):
            self.assertIn(kind, text, f"rule kind {kind} not documented")

    def test_limitations_documented(self):
        text = _readme().lower()
        for word in ("partial", "blind", "candidate", "emit-only"):
            self.assertIn(word, text, f"limitation term {word!r} missing from README")

    def test_loaded_count_is_dynamic(self):
        text = _readme().lower()
        self.assertIn("loaded", text)


if __name__ == "__main__":
    unittest.main()
