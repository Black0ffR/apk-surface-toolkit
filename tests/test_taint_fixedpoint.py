"""TF-02 Stages 2-3 regression tests: CFG fixed-point intra-method taint.

In-memory method bodies and tiny synthetic trees only; no APK execution.
Covers the approved test categories: straight-line compatibility, conditional
branches, conservative merges, unreachable blocks, loops, missing labels,
register overwrites, wide registers, coverage propagation, determinism.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from triagekit import analyzer as AN
from triagekit import rules as R
from triagekit import smali_parse as SP
from triagekit import taint_smali as TS

INV_SRC = ("    invoke-virtual {p0}, Landroid/content/Intent;->"
           "getStringExtra(Ljava/lang/String;)Ljava/lang/String;")
INV_SINK = "    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"
INV_SINK_V2 = "    invoke-virtual {p0, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"
INV_SINK_V5 = "    invoke-virtual {p0, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"


def _pats():
    return (TS.compile_matchers(["getStringExtra"], "sources"),
            TS.compile_matchers(["loadUrl"], "sinks"))


def _analyze(lines, visit_cap=None):
    src, sink = _pats()
    counters: dict = {}
    hits = TS._analyze_method(lines, src, sink, counters, visit_cap=visit_cap)
    return hits, counters


def _tree(root: str, body: str) -> str:
    d = os.path.join(root, "smali", "com", "example")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "A.smali"), "w", encoding="utf-8") as f:
        f.write(".class public Lcom/example/A;\n.super Ljava/lang/Object;\n\n"
                ".method public go()V\n    .locals 6\n" + body
                + "    return-void\n.end method\n")
    return os.path.join(root, "smali")


def _rule():
    return R.Rule({"id": "AS-0033", "title": "t", "kind": "smali-taint",
                   "severity": "high",
                   "params": {"sources": ["getStringExtra"],
                              "sinks": ["loadUrl"], "cap": 15},
                   "recommendation": "x"}, path="synthetic")


class TestStraightLine(unittest.TestCase):
    def test_straight_line_flow_still_found(self):
        hits, counters = _analyze([INV_SRC, "    move-result-object v0", INV_SINK])
        self.assertEqual([h["reg"] for h in hits], ["v0"])
        self.assertEqual(hits[0]["src_line"], 0)
        self.assertEqual(hits[0]["sink_line"], 2)
        self.assertEqual(counters, {"unsupported_instructions": 0,
                                    "malformed_instructions": 0,
                                    "missing_labels": 0,
                                    "unresolved_switches": 0, "capped": 0})

    def test_straight_line_kill_still_empty(self):
        hits, _ = _analyze([INV_SRC, "    move-result-object v0",
                            '    const-string v0, "safe"', INV_SINK])
        self.assertEqual(hits, [])


class TestBranches(unittest.TestCase):
    def test_flow_across_merge_is_found(self):
        body = [
            "    if-eqz p0, :branch",
            "    goto :merge",
            "    :branch",
            INV_SRC,
            "    move-result-object v0",
            "    :merge",
            INV_SINK,
        ]
        hits, counters = _analyze(body)
        self.assertEqual(len(hits), 1, hits)
        self.assertEqual(hits[0]["src_line"], 3)
        self.assertEqual(hits[0]["sink_line"], 6)
        self.assertEqual(counters["missing_labels"], 0)

    def test_merge_keeps_taint_killed_on_only_one_path(self):
        """Path A kills v0, path B still carries it: the join must keep the
        taint (T+U=T), unlike the old single-pass linear order."""
        body = [
            INV_SRC,
            "    move-result-object v0",
            "    if-eqz p0, :keep",
            '    const-string v0, "safe"',
            "    :keep",
            INV_SINK,
        ]
        hits, _ = _analyze(body)
        self.assertEqual(len(hits), 1, hits)
        self.assertEqual(hits[0]["reg"], "v0")

    def test_goto_skips_intervening_kill(self):
        body = [
            INV_SRC,
            "    move-result-object v0",
            "    goto :next",
            '    const-string v0, "safe"',
            "    :next",
            INV_SINK,
        ]
        hits, counters = _analyze(body)
        self.assertEqual(len(hits), 1, hits)
        self.assertEqual(counters["missing_labels"], 0)

    def test_two_source_paths_merge_deterministically(self):
        body = [
            "    if-eqz p0, :a",
            INV_SRC,
            "    move-result-object v0",
            "    goto :merge",
            "    :a",
            INV_SRC,
            "    move-result-object v0",
            "    :merge",
            INV_SINK,
        ]
        first, _ = _analyze(body)
        second, _ = _analyze(body)
        self.assertEqual(len(first), 1, first)
        self.assertEqual(first, second)
        self.assertEqual(first[0]["src_line"], 1,
                         "merge must keep both entries and report the "
                         "deterministic first one")


class TestUnreachable(unittest.TestCase):
    def test_dead_code_after_return_is_not_analyzed(self):
        body = [
            "    return-void",
            "    :dead",
            INV_SRC,
            "    move-result-object v0",
            INV_SINK,
            "    return-void",
        ]
        hits, counters = _analyze(body)
        self.assertEqual(hits, [], "unreachable block must not yield findings")
        self.assertEqual(counters["capped"], 0)


class TestLoops(unittest.TestCase):
    def test_back_edge_enables_sink_before_source(self):
        """The sink is textually before the source; only the loop back edge
        makes the flow real (the linear scan cannot see it)."""
        body = [
            "    :head",
            INV_SINK,
            INV_SRC,
            "    move-result-object v0",
            "    goto :head",
        ]
        hits, counters = _analyze(body)
        self.assertEqual(len(hits), 1, hits)
        self.assertEqual(hits[0]["src_line"], 2)
        self.assertEqual(hits[0]["sink_line"], 1)
        self.assertEqual(counters["capped"], 0)

    def test_loop_converges_without_cap(self):
        body = [
            "    :top",
            INV_SINK,
            "    if-eqz p0, :exit",
            INV_SRC,
            "    move-result-object v0",
            INV_SINK,
            "    goto :top",
            "    :exit",
            "    return-void",
        ]
        hits, counters = _analyze(body)
        self.assertEqual(counters["capped"], 0)
        self.assertEqual({(h["src_line"], h["sink_line"]) for h in hits},
                         {(3, 1), (3, 5)})


class TestMissingLabel(unittest.TestCase):
    def test_missing_label_is_gap_not_fallthrough(self):
        body = [
            INV_SRC,
            "    move-result-object v0",
            "    goto :nowhere",
            INV_SINK,
            "    return-void",
        ]
        hits, counters = _analyze(body)
        self.assertEqual(hits, [], "no invented successor for a missing label")
        self.assertEqual(counters, {"unsupported_instructions": 0,
                                    "malformed_instructions": 0,
                                    "missing_labels": 1,
                                    "unresolved_switches": 0, "capped": 0})


class TestSwitches(unittest.TestCase):
    def test_switch_case_edges_carry_taint(self):
        body = [
            INV_SRC,
            "    move-result-object v0",
            "    packed-switch v0, :data",
            "    goto :done",
            "    :case1",
            INV_SINK,
            "    :done",
            "    return-void",
            "    :data",
            "    .packed-switch 0x0",
            "    :case1",
            "    .end packed-switch",
        ]
        hits, counters = _analyze(body)
        self.assertEqual(len(hits), 1, hits)
        self.assertEqual(counters["unresolved_switches"], 0)
        self.assertEqual(counters["missing_labels"], 0)

    def test_unresolved_switch_is_counted(self):
        body = [
            INV_SRC,
            "    move-result-object v0",
            "    packed-switch v0, :missing_data",
            INV_SINK,
            "    return-void",
        ]
        hits, counters = _analyze(body)
        self.assertEqual(counters["unresolved_switches"], 1)
        self.assertEqual(counters["missing_labels"], 1)


class TestWideAndOverwrite(unittest.TestCase):
    def test_wide_pair_flow_across_branch_merge(self):
        body = [
            INV_SRC,
            "    move-result-wide v0",
            "    if-eqz p0, :skip",
            "    move-wide v4, v0",
            "    :skip",
            INV_SINK_V5,
        ]
        hits, _ = _analyze(body)
        self.assertEqual([h["reg"] for h in hits], ["v5"])

    def test_wide_const_kill_in_block(self):
        body = [
            INV_SRC,
            "    move-result-wide v0",
            "    const-wide v0, 0x0",
            "    invoke-virtual {p0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
        ]
        hits, _ = _analyze(body)
        self.assertEqual(hits, [])


class TestCapAndDeterminism(unittest.TestCase):
    def test_visit_cap_marks_capped_and_keeps_partial_hits(self):
        body = [
            "    :head",
            INV_SRC,
            "    move-result-object v0",
            INV_SINK,
            "    goto :head",
        ]
        hits, counters = _analyze(body, visit_cap=1)
        self.assertEqual(counters["capped"], 1)
        self.assertEqual(len(hits), 1, "results before the cap must be kept")

    def test_no_cap_on_small_loop(self):
        body = ["    :head", INV_SRC, "    move-result-object v0", INV_SINK,
                "    goto :head"]
        _, counters = _analyze(body)
        self.assertEqual(counters["capped"], 0)

    def test_analysis_is_deterministic(self):
        body = [
            "    :top",
            INV_SINK,
            "    if-eqz p0, :exit",
            INV_SRC,
            "    move-result-object v0",
            INV_SINK,
            "    goto :top",
            "    :exit",
            "    return-void",
        ]
        first_hits, first_counters = _analyze(body)
        second_hits, second_counters = _analyze(body)
        self.assertEqual(first_hits, second_hits)
        self.assertEqual(first_counters, second_counters)


class TestCoveragePropagation(unittest.TestCase):
    def test_scan_stats_surface_new_counters(self):
        body = INV_SRC + "\n    move-result-object v0\n    goto :nowhere\n" + INV_SINK + "\n"
        with tempfile.TemporaryDirectory() as td:
            decoded = _tree(td, body)
            stats: dict = {}
            TS.scan(decoded, [_rule()], stats=stats)
        for key in ("missing_labels", "unresolved_switches", "cfg_capped_any"):
            self.assertIn(key, stats)
        self.assertGreaterEqual(stats["missing_labels"], 1)
        self.assertFalse(stats["cfg_capped_any"])

    def _taint_stage(self, taint_stats):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"manifest", "regex", "smali-taint"},
            taint_stats=taint_stats)
        return [s for s in stages if s["stage"] == "smali-taint"][0]

    def test_missing_labels_make_stage_partial(self):
        taint = self._taint_stage({"methods_scanned": 2,
                                   "truncated_any": False,
                                   "missing_labels": 1})
        self.assertFalse(taint["complete"])
        self.assertIn("missing branch label", taint["reason"])

    def test_unresolved_switches_make_stage_partial(self):
        taint = self._taint_stage({"methods_scanned": 2,
                                   "truncated_any": False,
                                   "unresolved_switches": 1})
        self.assertFalse(taint["complete"])
        self.assertIn("unresolved switch", taint["reason"])

    def test_cfg_capped_makes_stage_partial(self):
        taint = self._taint_stage({"methods_scanned": 2,
                                   "truncated_any": False,
                                   "cfg_capped_any": True})
        self.assertFalse(taint["complete"])
        self.assertIn("visit cap", taint["reason"])

    def test_absent_new_counters_default_to_complete(self):
        taint = self._taint_stage({"methods_scanned": 2,
                                   "truncated_any": False})
        self.assertTrue(taint["complete"], taint)


class _Blk:
    def __init__(self, start, end):
        self.start_line = start
        self.end_line = end


class TestArrayDataPolicy(unittest.TestCase):
    """fill-array-data must yield UNKNOWN like aget: an array write cannot be
    treated as a clean kill of a tainted register."""

    def _entry(self, reg):
        return {"line": 0, "method": "m", "owner": "Lx;",
                "matcher": {"mode": "name", "owner": "Lx;", "name": "s"},
                "path": [reg]}

    def test_fast_transfer_fill_array_data_yields_unknown(self):
        items = SP.parse_lines([
            "    fill-array-data v0, :array_0",
            "    aget v2, v3, v4",
        ])
        out, _ = TS._transfer(_Blk(0, 1), items,
                              {"v0": (self._entry("v0"),)}, [], [])
        self.assertIs(out["v0"], TS.UNKNOWN)
        self.assertIs(out["v2"], TS.UNKNOWN)

    def test_interop_transfer_fill_array_data_yields_unknown(self):
        items = SP.parse_lines(["    fill-array-data v0, :array_0"])
        out, _ = TS._ip_transfer(_Blk(0, 0), items,
                                 {"v0": (self._entry("v0"),)}, {})
        self.assertIs(out["v0"], TS.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
