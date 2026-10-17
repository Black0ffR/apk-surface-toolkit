"""TF-01 regression tests. In-memory method bodies only, no APK execution."""
from __future__ import annotations

import unittest

from triagekit import taint_smali as TS


def _pats():
    return (TS.compile_matchers(["getStringExtra"], "sources"),
            TS.compile_matchers(["loadUrl"], "sinks"))


class TestStaleTaintKill(unittest.TestCase):
    def test_overwrite_with_untainted_clears_taint(self):
        """Plan example: getStringExtra->v0, then move v0,v1(safe), then loadUrl(v0) = no flow."""
        src_pat, sink_pat = _pats()
        lines = [
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-object v0",
            '    const-string v1, "safe"',
            "    move-object v0, v1",
            "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        self.assertEqual(TS._scan_method(lines, src_pat, sink_pat), [])

    def test_tainted_copy_still_propagates(self):
        src_pat, sink_pat = _pats()
        lines = [
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-object v0",
            "    move-object v2, v0",
            "    invoke-virtual {p0, v2}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        hits = TS._scan_method(lines, src_pat, sink_pat)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["reg"], "v2")

    def test_const_overwrite_clears_taint(self):
        src_pat, sink_pat = _pats()
        lines = [
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-object v0",
            "    const-string v0, \"safe\"",
            "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        self.assertEqual(TS._scan_method(lines, src_pat, sink_pat), [])

    def test_move_from16_overwrite_clears(self):
        src_pat, sink_pat = _pats()
        lines = [
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-object v0",
            "    move/from16 v0, v1",
            "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        self.assertEqual(TS._scan_method(lines, src_pat, sink_pat), [])

    def test_move16_and_move_object_variants(self):
        src_pat, sink_pat = _pats()
        for op in ("move/16 v0, v1", "move-object/from16 v0, v1", "move-wide v0, v1"):
            with self.subTest(op=op):
                lines = [
                    "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                    "    move-result-object v0",
                    f"    {op}",
                    "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
                ]
                self.assertEqual(
                    TS._scan_method(lines, src_pat, sink_pat),
                    [],
                    f"{op} must kill stale taint",
                )

class TestWidePairs(unittest.TestCase):
    def test_wide_overwrite_clears_second_register(self):
        """`move-wide v0, v2` writes the pair (v0,v1): a tainted v1 must clear."""
        src_pat, sink_pat = _pats()
        lines = [
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-object v1",
            "    move-wide v0, v2",
            "    invoke-virtual {p0, v1}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        hits = TS._scan_method(lines, src_pat, sink_pat)
        self.assertEqual(
            [h for h in hits if h["reg"] == "v1"], [],
            f"stale taint survived in second wide register: {hits}")

    def test_wide_copy_propagates_pair(self):
        src_pat, sink_pat = _pats()
        lines = [
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-wide v0",
            "    move-wide v4, v0",
            "    invoke-virtual {p0, v5}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        hits = TS._scan_method(lines, src_pat, sink_pat)
        self.assertTrue(any(h["reg"] == "v5" for h in hits), f"wide pair not propagated: {hits}")

    def test_const_wide_clears_pair(self):
        src_pat, sink_pat = _pats()
        for op in ("const-wide v0, 0x0", "const-wide/high16 v0, 0x0"):
            with self.subTest(op=op):
                lines = [
                    "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                    "    move-result-object v0",
                    f"    {op}",
                    "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
                ]
                self.assertEqual(TS._scan_method(lines, src_pat, sink_pat), [],
                                 f"{op} must clear the wide pair")

    def test_move_result_wide_fresh_kills_pair(self):
        src_pat, sink_pat = _pats()
        lines = [
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-object v1",
            "    invoke-virtual {p0}, Lx/Other;->safe()J",
            "    move-result-wide v0",
            "    invoke-virtual {p0, v1}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        self.assertEqual(TS._scan_method(lines, src_pat, sink_pat), [])

    def test_move_result_fresh_kills_narrow(self):
        src_pat, sink_pat = _pats()
        lines = [
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-object v0",
            "    invoke-virtual {p0}, Lx/Other;->safe()Ljava/lang/String;",
            "    move-result-object v0",
            "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        self.assertEqual(TS._scan_method(lines, src_pat, sink_pat), [])


if __name__ == "__main__":
    unittest.main()
