"""TF-03 regression tests: structured matchers, owner enforcement, argument
mapping, coverage counters, register-path detail. In-memory bodies and tiny
synthetic trees only; no APK execution.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from triagekit import rules as R
from triagekit import taint_smali as TS

INV_SRC = ("    invoke-virtual {p0}, Landroid/content/Intent;->"
           "getStringExtra(Ljava/lang/String;)Ljava/lang/String;")
INV_SINK = "    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"
INV_STATIC_SINK = "    invoke-static {v0, v1}, Lx/Sinks;->handle(Ljava/lang/String;I)V"


def _src(entries):
    return TS.compile_matchers(entries, "sources")


def _sink(entries):
    return TS.compile_matchers(entries, "sinks")


def _tree(root: str, body: str) -> str:
    d = os.path.join(root, "smali", "com", "example")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "A.smali"), "w", encoding="utf-8") as f:
        f.write(".class public Lcom/example/A;\n.super Ljava/lang/Object;\n\n"
                ".method public go()V\n    .locals 2\n" + body
                + "    return-void\n.end method\n")
    return os.path.join(root, "smali")


def _rule(sources, sinks, **params):
    p = {"sources": sources, "sinks": sinks, "cap": 15}
    p.update(params)
    return R.Rule({"id": "AS-0033", "title": "t", "kind": "smali-taint",
                   "severity": "high", "params": p, "recommendation": "x"},
                  path="synthetic")


class TestCompileMatchers(unittest.TestCase):
    def test_legacy_string_is_literal_name_mode(self):
        m = _src(["getStringExtra"])[0]
        self.assertEqual(m["mode"], "name")
        self.assertEqual(m["name"], "getStringExtra")
        self.assertIsNone(m["owner"])

    def test_owner_implies_owner_name_mode(self):
        m = _sink([{"owner": "Lx/WebView;", "name": "loadUrl"}])[0]
        self.assertEqual(m["mode"], "owner-name")
        self.assertEqual(m["owner"], "Lx/WebView;")

    def test_explicit_modes_preserved(self):
        m = _sink([{"name": "load.*", "match": "regex"}])[0]
        self.assertEqual(m["mode"], "regex")
        self.assertIsNotNone(m["regex"])

    def test_argument_indexes_normalized_for_sinks(self):
        m = _sink([{"name": "loadUrl", "argument_indexes": [0, 1]}])[0]
        self.assertEqual(m["argument_indexes"], [0, 1])

    def test_argument_indexes_rejected_for_sources(self):
        with self.assertRaises(ValueError):
            _src([{"name": "x", "argument_indexes": [0]}])

    def test_bad_entries_raise(self):
        with self.assertRaises(ValueError):
            _src([{"owner": "Lx/A;"}])
        with self.assertRaises(ValueError):
            _src([{"name": "x", "match": "glob"}])
        with self.assertRaises(ValueError):
            _src([42])

    def test_empty_entries_yield_no_matchers(self):
        self.assertEqual(_src([]), [])


class TestLiteralMatching(unittest.TestCase):
    def test_dollar_is_literal_not_anchor(self):
        body = ["    invoke-virtual {p0}, Lx/In;->getData$()Ljava/lang/String;",
                "    move-result-object v0",
                "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V"]
        hits = TS._scan_method(body, _src(["getData$"]), _sink(["loadUrl"]))
        self.assertEqual(len(hits), 1)
        hits = TS._scan_method(body, _src(["getData"]), _sink(["loadUrl"]))
        self.assertEqual(hits, [])

    def test_dot_is_literal_unless_regex_mode(self):
        body = ["    invoke-virtual {p0}, Lx/In;->getXData()Ljava/lang/String;",
                "    move-result-object v0",
                "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V"]
        hits = TS._scan_method(body, _src(["get.Data"]), _sink(["loadUrl"]))
        self.assertEqual(hits, [])
        hits = TS._scan_method(body, _src(["get.Data"]), _sink(["loadUrl"]))
        self.assertEqual(hits, [], "literal again; regex must be opt-in")

    def test_regex_mode_matches_when_opted_in(self):
        body = ["    invoke-virtual {p0}, Lx/In;->getXData()Ljava/lang/String;",
                "    move-result-object v0",
                "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V"]
        hits = TS._scan_method(body, _src([{"name": "get.Data", "match": "regex"}]),
                               _sink(["loadUrl"]))
        self.assertEqual(len(hits), 1)


class TestOwnerEnforcement(unittest.TestCase):
    def test_owner_restricted_source_rejects_other_class(self):
        matchers = _src([{"owner": "Landroid/content/Intent;",
                          "name": "getStringExtra"}])
        body = ["    invoke-virtual {p0}, Lx/Other;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                "    move-result-object v0", INV_SINK]
        self.assertEqual(TS._scan_method(body, matchers, _sink(["loadUrl"])), [])

    def test_owner_restricted_source_matches_own_class(self):
        matchers = _src([{"owner": "Landroid/content/Intent;",
                          "name": "getStringExtra"}])
        hits = TS._scan_method([INV_SRC, "    move-result-object v0", INV_SINK],
                               matchers, _sink(["loadUrl"]))
        self.assertEqual(len(hits), 1)

    def test_name_mode_matches_any_owner(self):
        hits = TS._scan_method(
            ["    invoke-virtual {p0}, Lx/Other;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
             "    move-result-object v0", INV_SINK],
            _src(["getStringExtra"]), _sink(["loadUrl"]))
        self.assertEqual(len(hits), 1)

    def test_name_mode_does_not_match_owner_substring(self):
        body = ["    invoke-virtual {p0}, Lx/getStringExtraHelper;->doThing(Ljava/lang/String;)Ljava/lang/String;",
                "    move-result-object v0", INV_SINK]
        self.assertEqual(TS._scan_method(body, _src(["getStringExtra"]),
                                         _sink(["loadUrl"])), [])

    def test_owner_restricted_sink_rejects_other_class(self):
        body = [INV_SRC, "    move-result-object v0",
                "    invoke-virtual {p0, v0}, Lx/OtherWebView;->loadUrl(Ljava/lang/String;)V"]
        self.assertEqual(TS._scan_method(body, _src(["getStringExtra"]),
                                         _sink([{"owner": "Landroid/webkit/WebView;",
                                                "name": "loadUrl"}])), [])


class TestArgumentIndexes(unittest.TestCase):
    def test_instance_flow_with_arg_index_1(self):
        sink = _sink([{"name": "loadUrl", "argument_indexes": [1]}])
        hits = TS._scan_method([INV_SRC, "    move-result-object v0", INV_SINK],
                               _src(["getStringExtra"]), sink)
        self.assertEqual([h["reg"] for h in hits], ["v0"])

    def test_instance_receiver_not_selected_by_arg_index_1(self):
        sink = _sink([{"name": "loadUrl", "argument_indexes": [1]}])
        body = [INV_SRC, "    move-result-object p0", INV_SINK]
        self.assertEqual(TS._scan_method(body, _src(["getStringExtra"]), sink), [])

    def test_instance_receiver_selected_by_arg_index_0(self):
        sink = _sink([{"name": "loadUrl", "argument_indexes": [0]}])
        body = [INV_SRC, "    move-result-object p0", INV_SINK]
        hits = TS._scan_method(body, _src(["getStringExtra"]), sink)
        self.assertEqual([h["reg"] for h in hits], ["p0"])

    def test_no_indexes_selects_any_register(self):
        body = [INV_SRC, "    move-result-object p0", INV_SINK]
        hits = TS._scan_method(body, _src(["getStringExtra"]), _sink(["loadUrl"]))
        self.assertEqual([h["reg"] for h in hits], ["p0"])

    def test_static_position_0_is_first_argument(self):
        sink = _sink([{"name": "handle", "argument_indexes": [0]}])
        hits = TS._scan_method([INV_SRC, "    move-result-object v0", INV_STATIC_SINK],
                               _src(["getStringExtra"]), sink)
        self.assertEqual([h["reg"] for h in hits], ["v0"])

    def test_static_position_1_is_second_argument(self):
        sink = _sink([{"name": "handle", "argument_indexes": [1]}])
        body = [INV_SRC, "    move-result-object v0", "    move-object v1, v0",
                INV_STATIC_SINK]
        hits = TS._scan_method(body, _src(["getStringExtra"]), sink)
        self.assertEqual([h["reg"] for h in hits], ["v1"])

    def test_out_of_range_index_selects_nothing(self):
        sink = _sink([{"name": "loadUrl", "argument_indexes": [5]}])
        self.assertEqual(TS._scan_method([INV_SRC, "    move-result-object v0", INV_SINK],
                                         _src(["getStringExtra"]), sink), [])
        sink = _sink([{"name": "handle", "argument_indexes": [7]}])
        self.assertEqual(TS._scan_method([INV_SRC, "    move-result-object v0",
                                          INV_STATIC_SINK],
                                         _src(["getStringExtra"]), sink), [])


class TestCoverageCounters(unittest.TestCase):
    def test_unsupported_instruction_counted(self):
        counters = {}
        body = [INV_SRC, "    move-result-object v0",
                "    invoke-custom {v1}, Lx;->noop()V", INV_SINK]
        hits = TS._scan_method(body, _src(["getStringExtra"]),
                               _sink(["loadUrl"]), counters)
        self.assertEqual(counters,
                         {"unsupported_instructions": 1, "malformed_instructions": 0})
        self.assertEqual(len(hits), 1, "coverage count must not suppress the flow")

    def test_malformed_instruction_counted(self):
        counters = {}
        TS._scan_method(["    move v0"], _src(["getStringExtra"]),
                        _sink(["loadUrl"]), counters)
        self.assertEqual(counters,
                         {"unsupported_instructions": 0, "malformed_instructions": 1})

    def test_irrelevant_lines_not_counted_as_gaps(self):
        counters = {}
        TS._scan_method(['    const-string v0, "x"', "    nop", "    return-void",
                         "    .locals 1", "    # comment"],
                        _src(["getStringExtra"]), _sink(["loadUrl"]), counters)
        self.assertEqual(counters,
                         {"unsupported_instructions": 0, "malformed_instructions": 0})

    def test_counters_optional(self):
        TS._scan_method([INV_SRC, "    move-result-object v0", INV_SINK],
                        _src(["getStringExtra"]), _sink(["loadUrl"]))


class TestScanFindings(unittest.TestCase):
    def test_register_path_and_match_provenance_in_detail(self):
        body = [INV_SRC, "    move-result-object v0", "    move-object v2, v0",
                "    invoke-virtual {p0, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"]
        with tempfile.TemporaryDirectory() as td:
            decoded = _tree(td, "".join(l + "\n" for l in body))
            rule = _rule([{"owner": "Landroid/content/Intent;", "name": "getStringExtra"}],
                         [{"owner": "Landroid/webkit/WebView;", "name": "loadUrl"}])
            out = TS.scan(decoded, [rule])
        self.assertEqual(len(out), 1, out)
        det = out[0]["detail"]
        self.assertEqual(det["register_path"], ["v0", "v2"])
        self.assertEqual(det["reg"], "v2")
        self.assertEqual(det["src_owner"], "Landroid/content/Intent;")
        self.assertEqual(det["sink_owner"], "Landroid/webkit/WebView;")
        self.assertEqual(det["source_match"],
                         {"mode": "owner-name", "owner": "Landroid/content/Intent;",
                          "name": "getStringExtra"})
        self.assertEqual(det["sink_match"],
                         {"mode": "owner-name", "owner": "Landroid/webkit/WebView;",
                          "name": "loadUrl"})
        for legacy in ("method", "sink", "reg", "src_method", "src_line", "sink_line"):
            self.assertIn(legacy, det)

    def test_stats_include_measured_zero_counters(self):
        body = [INV_SRC, "    move-result-object v0", INV_SINK]
        with tempfile.TemporaryDirectory() as td:
            decoded = _tree(td, "".join(l + "\n" for l in body))
            stats: dict = {}
            out = TS.scan(decoded, [_rule(["getStringExtra"], ["loadUrl"])], stats=stats)
        self.assertEqual(len(out), 1)
        self.assertEqual(stats["unsupported_instructions"], 0)
        self.assertEqual(stats["malformed_instructions"], 0)
        self.assertEqual(stats["methods_skipped"], 0)
        self.assertGreaterEqual(stats["methods_scanned"], 1)

    def test_gap_counts_reach_finding_reason_and_stats(self):
        body = [INV_SRC, "    move-result-object v0",
                "    invoke-custom {v1}, Lx;->noop()V", INV_SINK]
        with tempfile.TemporaryDirectory() as td:
            decoded = _tree(td, "".join(l + "\n" for l in body))
            stats: dict = {}
            out = TS.scan(decoded, [_rule(["getStringExtra"], ["loadUrl"])], stats=stats)
        self.assertEqual(len(out), 1)
        reason = out[0]["detail"]["analysis"]["reason"]
        self.assertIn("unsupported", reason.lower())
        self.assertGreaterEqual(stats["unsupported_instructions"], 1)

    def test_clean_method_reason_has_no_gap_text(self):
        body = [INV_SRC, "    move-result-object v0", INV_SINK]
        with tempfile.TemporaryDirectory() as td:
            decoded = _tree(td, "".join(l + "\n" for l in body))
            out = TS.scan(decoded, [_rule(["getStringExtra"], ["loadUrl"])])
        reason = out[0]["detail"]["analysis"]["reason"]
        self.assertNotIn("unsupported", reason.lower())
        self.assertNotIn("malformed", reason.lower())

    def test_malformed_method_declaration_is_skipped_and_counted(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "smali", "com", "example")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "A.smali"), "w", encoding="utf-8") as f:
                f.write(".class public Lcom/example/A;\n.super Ljava/lang/Object;\n\n"
                        ".method public broken\n"
                        + INV_SRC + "\n    move-result-object v0\n" + INV_SINK + "\n"
                        "    return-void\n.end method\n")
            stats: dict = {}
            out = TS.scan(os.path.join(td, "smali"),
                          [_rule(["getStringExtra"], ["loadUrl"])], stats=stats)
        self.assertEqual(out, [], "unparseable method must not produce findings")
        self.assertEqual(stats["methods_skipped"], 1)

    def test_bad_matcher_reports_finding_not_crash(self):
        rule = _rule([{"name": "([unclosed", "match": "regex"}], ["loadUrl"])
        with tempfile.TemporaryDirectory() as td:
            decoded = _tree(td, "")
            out = TS.scan(decoded, [rule])
        self.assertEqual(len(out), 1)
        self.assertIn("bad taint matcher", out[0]["evidence"])


GETINTENT = ("    invoke-virtual {p0}, Landroid/app/Activity;->"
             "getIntent()Landroid/content/Intent;")
START_ACTIVITY = ("    invoke-virtual {p0, v0}, Landroid/content/Context;->"
                  "startActivity(Landroid/content/Intent;)V")
REBIND = ("    invoke-virtual {v0, v1}, Landroid/content/Intent;->"
          "setClass(Landroid/content/Context;Ljava/lang/Class;)"
          "Landroid/content/Intent;")


class TestSelfRelaunchDiscrimination(unittest.TestCase):
    def test_helper_positive_for_passthrough_getintent(self):
        self.assertTrue(TS._self_relaunch(
            {"name": "getIntent"}, {"name": "startActivity"}, 5, 9, []))

    def test_helper_rejects_rebinding_between(self):
        self.assertFalse(TS._self_relaunch(
            {"name": "getIntent"}, {"name": "startActivity"}, 5, 9, [7]))

    def test_helper_rejects_non_getintent_source(self):
        self.assertFalse(TS._self_relaunch(
            {"name": "getStringExtra"}, {"name": "startActivity"}, 5, 9, []))

    def test_helper_rejects_non_start_sink(self):
        self.assertFalse(TS._self_relaunch(
            {"name": "getIntent"}, {"name": "loadUrl"}, 5, 9, []))

    def _scan(self, body, **params):
        with tempfile.TemporaryDirectory() as td:
            decoded = _tree(td, body)
            stats: dict = {}
            out = TS.scan(decoded,
                          [_rule(["getIntent"], ["startActivity"], **params)],
                          stats=stats)
        return out, stats

    def test_default_annotates_relaunch_as_candidate(self):
        body = GETINTENT + "\n    move-result-object v0\n" + START_ACTIVITY + "\n"
        out, stats = self._scan(body)
        self.assertEqual(len(out), 1, out)
        self.assertIs(out[0]["detail"]["self_relaunch"], True)
        self.assertEqual(out[0]["detail"]["analysis"]["classification"],
                         "self-relaunch")
        self.assertEqual(stats["self_relaunch"], 1)
        self.assertEqual(stats["self_relaunch_suppressed"], 0)

    def test_opt_in_suppresses_relaunch_finding(self):
        body = GETINTENT + "\n    move-result-object v0\n" + START_ACTIVITY + "\n"
        out, stats = self._scan(body, suppress_self_relaunch=True)
        self.assertEqual(out, [])
        self.assertEqual(stats["self_relaunch"], 1)
        self.assertEqual(stats["self_relaunch_suppressed"], 1)

    def test_rebinding_keeps_finding_as_redirect(self):
        body = (GETINTENT + "\n    move-result-object v0\n"
                + REBIND + "\n" + START_ACTIVITY + "\n")
        out, stats = self._scan(body, suppress_self_relaunch=True)
        self.assertEqual(len(out), 1, out)
        self.assertNotIn("self_relaunch", out[0]["detail"])
        self.assertEqual(stats["self_relaunch"], 0)
        self.assertEqual(stats["self_relaunch_suppressed"], 0)


if __name__ == "__main__":
    unittest.main()
