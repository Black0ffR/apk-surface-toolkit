"""B2 regression tests. Synthetic fixtures only; no APK execution."""
from __future__ import annotations

import os
import tempfile
import unittest

from triagekit import analyzer as AN
from triagekit import rules as R
from triagekit import taint_smali as TS


def _smali_tree(root: str) -> str:
    d = os.path.join(root, "smali", "com", "example")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "A.smali"), "w", encoding="utf-8") as f:
        f.write(
            ".class public Lcom/example/A;\n.super Ljava/lang/Object;\n\n"
            ".method public go()V\n    .locals 2\n"
            "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n"
            "    move-result-object v0\n"
            "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V\n"
            "    return-void\n.end method\n"
        )
    return os.path.join(root, "smali")


def _taint_rule():
    return R.Rule(
        {
            "id": "AS-0033",
            "title": "Attacker input reaches WebView sink",
            "kind": "smali-taint",
            "severity": "high",
            "params": {"sources": ["getStringExtra"], "sinks": ["loadUrl"], "cap": 15},
            "recommendation": "validate",
        },
        path="synthetic",
    )


class TestTaintScope(unittest.TestCase):
    def test_scope_descriptor_is_explicit(self):
        scope = TS.analysis_scope()
        self.assertEqual(scope["kind"], "intra_method_register_taint")
        self.assertFalse(scope["interprocedural"])
        self.assertTrue(scope["control_flow_aware"])
        self.assertIn("branch", " ".join(scope["limitations"]).lower())

    def test_findings_carry_scope_and_candidate_confidence(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _smali_tree(td)
            out = TS.scan(decoded, [_taint_rule()])
        self.assertTrue(out, "fixture should produce one flow")
        analysis = out[0].get("detail", {}).get("analysis", {})
        self.assertEqual(analysis.get("kind"), "intra_method_register_taint")
        self.assertFalse(analysis.get("interprocedural"))
        self.assertTrue(analysis.get("control_flow_aware"))
        # A static taint hit is a hypothesis, never verified proof.
        self.assertEqual(analysis.get("confidence"), "candidate")
        self.assertIn(analysis.get("status"), ("complete", "partial"))

    def test_stats_distinguish_negative_from_unscanned(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _smali_tree(td)
            stats_hit = {}
            TS.scan(decoded, [_taint_rule()], stats=stats_hit)
            self.assertGreater(stats_hit.get("methods_scanned", 0), 0)
            # A rule whose sink never appears: negative, but methods ran.
            rule = _taint_rule()
            rule.params["sinks"] = ["definitelyNotASinkXYZ"]
            stats_neg = {}
            out = TS.scan(decoded, [rule], stats=stats_neg)
            self.assertEqual(out, [])
            self.assertGreater(stats_neg.get("methods_scanned", 0), 0)
            # An empty/missing tree: nothing analysed at all.
            stats_empty = {}
            with tempfile.TemporaryDirectory() as td2:
                out2 = TS.scan(os.path.join(td2, "nosuchdir"), [_taint_rule()], stats=stats_empty)
            self.assertEqual(out2, [])
            self.assertEqual(stats_empty.get("methods_scanned", 0), 0)


def _stages_all_ok():
    return AN.compute_stages(
        decoded_ok=True, has_manifest=True, manifest_only=False,
        do_regex=True, packed=[], has_so_files=True,
        kinds_present={"manifest", "regex", "smali-taint", "reachability"},
        taint_stats={"methods_scanned": 5, "truncated_any": False},
        reach_coverage={"traversal_truncated_any": False,
                        "build_stats": {"unparsed_invokes": 0, "malformed_methods": 0,
                                        "calls_legacy_fallback": 0}},
        regex_stats={"truncated_any": False},
        native_stats={"truncated_any": False},
    )


class TestReportStatus(unittest.TestCase):
    def test_status_vocabulary(self):
        complete = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[], rule_errors=[],
            stages=_stages_all_ok(),
        )
        self.assertEqual(complete["status"], "complete")
        partial = AN.build_analysis_status(
            decoded_ok=True, manifest_only=True, packed=[], rule_errors=[],
            stages=AN.compute_stages(
                decoded_ok=True, has_manifest=True, manifest_only=True,
                do_regex=True, packed=[], has_so_files=True,
                kinds_present={"manifest", "regex", "smali-taint", "reachability"}),
        )
        self.assertEqual(partial["status"], "partial")
        self.assertTrue(any("manifest-only" in lim.lower() for lim in partial["limitations"]))
        packed = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=["jiagu"], rule_errors=[],
            stages=AN.compute_stages(
                decoded_ok=True, has_manifest=True, manifest_only=False,
                do_regex=True, packed=["jiagu"], has_so_files=False,
                kinds_present={"manifest"}),
        )
        self.assertEqual(packed["status"], "partial")
        missing = AN.build_analysis_status(
            decoded_ok=False, manifest_only=False, packed=[], rule_errors=["x"],
            stages=AN.compute_stages(
                decoded_ok=False, has_manifest=False, manifest_only=False,
                do_regex=True, packed=[], has_so_files=False, kinds_present=set()),
        )
        self.assertIn(missing["status"], ("partial", "not_analysed"))
        # Taint limitations must be named wherever code ran or was skipped.
        for st in (complete, partial):
            joined = " ".join(st["limitations"]).lower()
            self.assertIn("intra-method", joined)


class TestStageReporting(unittest.TestCase):
    def test_native_not_marked_run_without_so_files(self):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"manifest", "regex", "smali-taint", "reachability"})
        native = next(s for s in stages if s["stage"] == "native")
        self.assertFalse(native["ran"])
        self.assertIn("no native", native["reason"].lower())
        st = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[], rule_errors=[],
            stages=stages)
        # No .so files means nothing to analyse: must not force partial.
        self.assertEqual(st["status"], "complete")

    def test_no_regex_marks_code_stages_not_run(self):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=False, packed=[], has_so_files=True,
            kinds_present={"manifest", "regex", "smali-taint", "reachability"})
        for name in ("regex", "smali-taint", "reachability", "native"):
            s = next(x for x in stages if x["stage"] == name)
            self.assertFalse(s["ran"], name)
        st = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[], rule_errors=[],
            stages=stages)
        self.assertEqual(st["status"], "partial")

    def test_truncated_taint_stage_is_partial(self):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"manifest", "regex", "smali-taint"},
            taint_stats={"methods_scanned": 9, "truncated_any": True})
        taint = next(s for s in stages if s["stage"] == "smali-taint")
        self.assertTrue(taint["ran"])
        self.assertFalse(taint["complete"])
        st = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[], rule_errors=[],
            stages=stages)
        self.assertEqual(st["status"], "partial")

    def test_truncated_reachability_stage_is_partial(self):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"manifest", "reachability"},
            reach_coverage={"traversal_truncated_any": True,
                            "build_stats": {"unparsed_invokes": 0,
                                            "malformed_methods": 0,
                                            "calls_legacy_fallback": 0}})
        reach = next(s for s in stages if s["stage"] == "reachability")
        self.assertFalse(reach["complete"])
        st = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[], rule_errors=[],
            stages=stages)
        self.assertEqual(st["status"], "partial")

    def test_parse_failures_make_reachability_partial(self):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"manifest", "reachability"},
            reach_coverage={"traversal_truncated_any": False,
                            "build_stats": {"unparsed_invokes": 2,
                                            "malformed_methods": 0,
                                            "calls_legacy_fallback": 0}})
        reach = next(s for s in stages if s["stage"] == "reachability")
        self.assertFalse(reach["complete"])
        self.assertIn("unparsed", reach["reason"].lower())

    def test_nothing_ran_is_not_analysed(self):
        stages = AN.compute_stages(
            decoded_ok=False, has_manifest=False, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False, kinds_present=set())
        st = AN.build_analysis_status(
            decoded_ok=False, manifest_only=False, packed=[], rule_errors=[],
            stages=stages)
        self.assertEqual(st["status"], "not_analysed")


class TestTaintCoverageStatus(unittest.TestCase):
    def _taint_stage(self, taint_stats):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"manifest", "regex", "smali-taint"},
            taint_stats=taint_stats, regex_stats={"truncated_any": False})
        return [s for s in stages if s["stage"] == "smali-taint"][0]

    def test_measured_zero_counters_complete(self):
        taint = self._taint_stage({"methods_scanned": 3, "truncated_any": False,
                                   "unsupported_instructions": 0,
                                   "malformed_instructions": 0,
                                   "methods_skipped": 0})
        self.assertTrue(taint["complete"], taint)

    def test_unsupported_instructions_make_stage_partial(self):
        taint = self._taint_stage({"methods_scanned": 3, "truncated_any": False,
                                   "unsupported_instructions": 2,
                                   "malformed_instructions": 0,
                                   "methods_skipped": 0})
        self.assertFalse(taint["complete"])
        self.assertIn("unsupported", taint["reason"])

    def test_malformed_instructions_make_stage_partial(self):
        taint = self._taint_stage({"methods_scanned": 3, "truncated_any": False,
                                   "unsupported_instructions": 0,
                                   "malformed_instructions": 1,
                                   "methods_skipped": 0})
        self.assertFalse(taint["complete"])
        self.assertIn("malformed", taint["reason"])

    def test_skipped_methods_make_stage_partial(self):
        taint = self._taint_stage({"methods_scanned": 3, "truncated_any": False,
                                   "unsupported_instructions": 0,
                                   "malformed_instructions": 0,
                                   "methods_skipped": 1})
        self.assertFalse(taint["complete"])
        self.assertIn("skipped", taint["reason"])

    def test_missing_counters_default_to_complete(self):
        taint = self._taint_stage({"methods_scanned": 5, "truncated_any": False})
        self.assertTrue(taint["complete"], taint)


class TestTaintReadCap(unittest.TestCase):
    def _stage(self, taint_stats):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"manifest", "regex", "smali-taint"},
            taint_stats=taint_stats, regex_stats={"truncated_any": False})
        return next(s for s in stages if s["stage"] == "smali-taint")

    def test_small_file_is_not_flagged_truncated(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _smali_tree(td)
            stats = {}
            TS.scan(decoded, [_taint_rule()], stats=stats)
        self.assertEqual(stats.get("files_truncated", 0), 0)
        self.assertTrue(self._stage(stats)["complete"])

    def test_file_over_read_cap_is_counted_and_stage_partial(self):
        # P5-D1 scenario: one >500KB method with an early return before the
        # read cap and the sink after it. The omitted tail must be recorded
        # as truncation, and the stage must not report a clean completion.
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "smali", "com", "example")
            os.makedirs(d, exist_ok=True)
            head = (
                ".class public Lcom/example/Big;\n.super Ljava/lang/Object;\n\n"
                ".method public big()V\n    .locals 2\n"
                "    invoke-virtual {p0}, Lx/Input;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n"
                "    move-result-object v0\n"
                "    return-void\n")
            pad = "".join("    # pad %06d\n" % i for i in range(40000))
            tail = (
                "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V\n"
                "    return-void\n.end method\n")
            with open(os.path.join(d, "Big.smali"), "w", encoding="utf-8") as f:
                f.write(head + pad + tail)
            decoded = os.path.join(td, "smali")
            stats = {}
            TS.scan(decoded, [_taint_rule()], stats=stats)
        self.assertEqual(stats.get("files_truncated"), 1)
        stage = self._stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("truncat", stage["reason"].lower())


class TestRegexReadCap(unittest.TestCase):
    def _rule(self):
        return R.Rule(
            {"id": "AS-0034", "title": "multiline pattern",
             "kind": "regex", "severity": "medium",
             "params": {"pattern": "secretToken", "multiline": True,
                        "exts": [".txt"]},
             "recommendation": "x"},
            path="synthetic")

    def _stage(self, stats):
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"manifest", "regex"},
            regex_stats=stats, taint_stats={})
        return next(s for s in stages if s["stage"] == "regex")

    def test_small_multiline_file_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "x")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "small.txt"), "w", encoding="utf-8") as f:
                f.write("secretToken\n")
            stats = {}
            out = AN.check_regex([self._rule()], td, stats=stats)
        self.assertTrue(out)
        self.assertEqual(stats.get("files_truncated", 0), 0)
        self.assertTrue(self._stage(stats)["complete"])

    def test_file_over_read_cap_is_counted_and_stage_partial(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "x")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "big.txt"), "w", encoding="utf-8") as f:
                f.write("secretToken\n")
                f.write("".join("pad line %06d\n" % i for i in range(40000)))
            stats = {}
            out = AN.check_regex([self._rule()], td, stats=stats)
        self.assertTrue(out, "match inside the readable portion is reported")
        self.assertEqual(stats.get("files_truncated"), 1)
        stage = self._stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("truncat", stage["reason"].lower())


if __name__ == "__main__":
    unittest.main()
