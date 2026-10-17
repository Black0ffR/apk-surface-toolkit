"""TF-02 Stage 4 regression tests: opt-in interprocedural taint summaries.

Synthetic smali trees and in-memory rules only; no APK execution. Covers the
approved Batch H categories: helper parameter->return propagation, helper
parameter->sink relations, overload identity, helper chains, recursion
bounds, unresolved-callee uncertainty, sanitizer modeling (resolved,
owner-scoped, argument-indexed, context-scoped, unresolved), summary
completeness/partial status, schema validation, and the default-off fast
scan staying byte-compatible.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from triagekit import analyzer as AN
from triagekit import rules as R
from triagekit import taint_smali as TS

INTENT_GET = ("    invoke-virtual {p0}, Landroid/content/Intent;->"
              "getStringExtra(Ljava/lang/String;)Ljava/lang/String;")
LOADURL = ("    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->"
           "loadUrl(Ljava/lang/String;)V")
MAIN_REL = "smali/com/example/app/MainActivity.smali"

INTEROP_KEYS = ("unresolved_calls", "sanitizers_unverified",
                "summaries_incomplete", "ambiguous_methods",
                "sanitizer_passages", "summaries_built")


def _write_smali(root: str, rel: str, text: str) -> None:
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _class(cls: str, methods: str) -> str:
    return f".class public {cls};\n.super Ljava/lang/Object;\n\n" + methods


def _rule(*, inter=False, sanitizers=None, sinks=None, sources=None,
          cap=15) -> R.Rule:
    params = {
        "sources": (sources if sources is not None
                    else [{"name": "getStringExtra", "match": "name"}]),
        "sinks": (sinks if sinks is not None
                  else [{"name": "loadUrl", "match": "name"}]),
        "cap": cap,
    }
    if inter:
        params["interprocedural"] = True
    if sanitizers is not None:
        params["sanitizers"] = sanitizers
    return R.Rule({"id": "AS-9301", "title": "t", "kind": "smali-taint",
                   "severity": "high", "params": params,
                   "recommendation": "x"}, path="synthetic")


def _taint_stage(taint_stats):
    stages = AN.compute_stages(
        decoded_ok=True, has_manifest=True, manifest_only=False,
        do_regex=True, packed=[], has_so_files=False,
        kinds_present={"manifest", "regex", "smali-taint"},
        taint_stats=taint_stats)
    return [s for s in stages if s["stage"] == "smali-taint"][0]


HELPER_IDENTITY = _class("Lcom/example/app/Helper;", """\
.method public static identity(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    move-object v0, p0
    return-object v0
.end method
""")

MAIN_CALL_IDENTITY = f"""\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
{INTENT_GET}
    move-result-object v0
    invoke-static {{v0}}, Lcom/example/app/Helper;->identity(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
{LOADURL}
    return-void
.end method
"""


class TestActivation(unittest.TestCase):
    def test_default_off_then_opt_in_helper_return(self):
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, MAIN_CALL_IDENTITY)
            _write_smali(td, "smali/com/example/app/Helper.smali",
                         HELPER_IDENTITY)
            fast = TS.scan(td, [_rule(inter=False)])
            stats: dict = {}
            inter = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(fast, [], "fast scan must not cross method bounds")
        self.assertEqual(len(inter), 1, inter)
        self.assertEqual(stats["summaries_built"], 1)
        self.assertEqual(stats["unresolved_calls"], 0)

    def test_fast_mode_ignores_sanitizer_declarations(self):
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, MAIN_CALL_IDENTITY)
            _write_smali(td, "smali/com/example/app/Helper.smali",
                         HELPER_IDENTITY)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=False,
                                     sanitizers=[{"name": "identity",
                                                  "match": "name"}])],
                          stats=stats)
        self.assertEqual(out, [])
        self.assertEqual(stats["sanitizers_unverified"], 0)
        self.assertEqual(stats["sanitizer_passages"], 0)


class TestHelperPropagation(unittest.TestCase):
    def test_cross_method_finding_shape_and_attribution(self):
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, MAIN_CALL_IDENTITY)
            _write_smali(td, "smali/com/example/app/Helper.smali",
                         HELPER_IDENTITY)
            out = TS.scan(td, [_rule(inter=True)])
        self.assertEqual(len(out), 1, out)
        det = out[0]["detail"]
        helper_sig = ("Lcom/example/app/Helper;->identity("
                      "Ljava/lang/String;)Ljava/lang/String;")
        self.assertEqual(out[0]["file"], MAIN_REL)
        self.assertIn("onCreate", det["method"])
        self.assertTrue(det["cross_method"])
        self.assertEqual(det["via"], [helper_sig])
        self.assertEqual(det["src_file"], MAIN_REL)
        self.assertEqual(det["sink_file"], MAIN_REL)
        self.assertEqual(det["src_line"], 5)
        self.assertEqual(det["sink_line"], 9)
        self.assertTrue(det["analysis"]["interprocedural"])
        self.assertIn("interprocedural",
                      det["analysis"]["reason"].lower())

    def test_helper_return_independent_of_argument_is_clean(self):
        helper = _class("Lcom/example/app/Const;", """\
.method public static constant(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    const-string v0, "safe"
    return-object v0
.end method
""")
        main = MAIN_CALL_IDENTITY.replace("Lcom/example/app/Helper;->identity",
                                          "Lcom/example/app/Const;->constant")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Const.smali", helper)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(out, [], "const-only helper return must stay clean")
        self.assertEqual(stats["unresolved_calls"], 0)
        self.assertEqual(stats["summaries_incomplete"], 0)
        self.assertTrue(_taint_stage(stats)["complete"])

    def test_overloaded_helpers_distinguished_by_descriptor(self):
        helper = _class("Lcom/example/app/Over;", """\
.method public static wrap(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    return-object p0
.end method

.method public static wrap(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1
    const-string v0, "safe"
    return-object v0
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public useString()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Over;->wrap(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method

.method public useObject()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Over;->wrap(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Over.smali", helper)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(len(out), 1, out)
        self.assertIn("useString", out[0]["detail"]["method"])
        self.assertEqual(stats["summaries_built"], 2)

    def test_helper_chain_reports_full_via(self):
        chain = _class("Lcom/example/app/Chain;", """\
.method public static inner(Ljava/lang/String;)V
    .locals 1
    invoke-static {p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method

.method public static outer(Ljava/lang/String;)V
    .locals 1
    invoke-static {p0}, Lcom/example/app/Chain;->inner(Ljava/lang/String;)V
    return-void
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Chain;->outer(Ljava/lang/String;)V
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Chain.smali", chain)
            out = TS.scan(td, [_rule(inter=True)])
        self.assertEqual(len(out), 1, out)
        det = out[0]["detail"]
        self.assertEqual(det["via"], [
            "Lcom/example/app/Chain;->outer(Ljava/lang/String;)V",
            "Lcom/example/app/Chain;->inner(Ljava/lang/String;)V",
        ])
        self.assertEqual(det["sink_file"], "smali/com/example/app/Chain.smali")
        self.assertEqual(det["sink_line"], 5)
        self.assertEqual(det["src_file"], MAIN_REL)
        self.assertEqual(out[0]["file"], MAIN_REL)
        self.assertTrue(det["cross_method"])

    def test_self_recursive_helper_relation_found_bounded(self):
        loop = _class("Lcom/example/app/Loop;", """\
.method public static rec(Ljava/lang/String;)V
    .locals 1
    invoke-static {p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-static {p0}, Lcom/example/app/Loop;->rec(Ljava/lang/String;)V
    return-void
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Loop;->rec(Ljava/lang/String;)V
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Loop.smali", loop)
            stats_a: dict = {}
            first = TS.scan(td, [_rule(inter=True)], stats=stats_a)
            stats_b: dict = {}
            second = TS.scan(td, [_rule(inter=True)], stats=stats_b)
        self.assertEqual(first, second, "interop scan must be deterministic")
        self.assertEqual(stats_a, stats_b)
        self.assertEqual(len(first), 1, first)
        self.assertEqual(first[0]["detail"]["via"],
                         ["Lcom/example/app/Loop;->rec(Ljava/lang/String;)V"])
        self.assertGreaterEqual(stats_a["summaries_incomplete"], 1)
        stage = _taint_stage(stats_a)
        self.assertFalse(stage["complete"])
        self.assertIn("interprocedural", stage["reason"].lower())

    def test_recursive_identity_return_stays_unknown(self):
        loop = _class("Lcom/example/app/Loop2;", """\
.method public static rec(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    invoke-static {p0}, Lcom/example/app/Loop2;->rec(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
""")
        main = MAIN_CALL_IDENTITY.replace(
            "Lcom/example/app/Helper;->identity",
            "Lcom/example/app/Loop2;->rec")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Loop2.smali", loop)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(out, [], "unproven recursive return must stay unknown")
        self.assertEqual(stats["unresolved_calls"], 0)
        self.assertGreaterEqual(stats["summaries_incomplete"], 1)

    def test_missing_helper_definition_stays_unknown(self):
        main = MAIN_CALL_IDENTITY.replace(
            "Lcom/example/app/Helper;->identity",
            "Lcom/example/app/Gone;->identity")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(out, [], "no fabricated flows through missing callees")
        self.assertEqual(stats["unresolved_calls"], 1)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"])
        self.assertIn("interprocedural gaps", stage["reason"])

    def test_multiple_callers_share_one_summary(self):
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public first()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Helper;->identity(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method

.method public second()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Helper;->identity(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Helper.smali",
                         HELPER_IDENTITY)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(len(out), 2, out)
        self.assertEqual(stats["summaries_built"], 1)

    def test_branch_dependent_helper_return_is_conservative_union(self):
        helper = _class("Lcom/example/app/Maybe;", """\
.method public static maybe(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    if-eqz p0, :keep
    const-string v0, "safe"
    goto :done
    :keep
    move-object v0, p0
    :done
    return-object v0
.end method
""")
        main = MAIN_CALL_IDENTITY.replace("Lcom/example/app/Helper;->identity",
                                          "Lcom/example/app/Maybe;->maybe")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Maybe.smali", helper)
            out = TS.scan(td, [_rule(inter=True)])
        self.assertEqual(len(out), 1, "a path returning the param keeps taint")
        self.assertTrue(out[0]["detail"]["cross_method"])

    def test_helper_internal_source_returned_to_caller_sink(self):
        fetch = _class("Lcom/example/app/Fetch;", """\
.method public static fetch()Ljava/lang/String;
    .locals 1
    invoke-virtual {v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
    invoke-static {}, Lcom/example/app/Fetch;->fetch()Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Fetch.smali", fetch)
            out = TS.scan(td, [_rule(inter=True)])
        self.assertEqual(len(out), 1, out)
        det = out[0]["detail"]
        fetch_sig = ("Lcom/example/app/Fetch;->fetch()Ljava/lang/String;")
        self.assertEqual(det["via"], [fetch_sig])
        self.assertEqual(det["src_file"], "smali/com/example/app/Fetch.smali")
        self.assertEqual(det["sink_file"], MAIN_REL)
        self.assertEqual(det["src_line"], 5)
        self.assertTrue(det["cross_method"])
        self.assertIn("via", out[0]["evidence"])


class TestSanitizers(unittest.TestCase):
    def _clean_tree(self):
        return _class("Lcom/example/app/Safe;", """\
.method public static clean(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    return-object p0
.end method
""")

    def test_resolved_sanitizer_suppresses_and_counts_passage(self):
        main = MAIN_CALL_IDENTITY.replace("Lcom/example/app/Helper;->identity",
                                          "Lcom/example/app/Safe;->clean")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Safe.smali",
                         self._clean_tree())
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True,
                                     sanitizers=[{"name": "clean",
                                                  "match": "name"}])],
                          stats=stats)
            control = TS.scan(td, [_rule(inter=True)])
        self.assertEqual(out, [], "verified sanitizer must suppress the flow")
        self.assertEqual(stats["sanitizer_passages"], 1)
        self.assertEqual(stats["sanitizers_unverified"], 0)
        self.assertTrue(_taint_stage(stats)["complete"], stats)
        self.assertEqual(len(control), 1, "control without sanitizer hits")

    def test_relation_hits_respect_sanitizer_suppression(self):
        sink_helper = _class("Lcom/example/app/Sink;", """\
.method public static send(Ljava/lang/String;)V
    .locals 1
    invoke-virtual {v0, p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public viaSinkHelper()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Safe;->clean(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Sink;->send(Ljava/lang/String;)V
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Safe.smali",
                         self._clean_tree())
            _write_smali(td, "smali/com/example/app/Sink.smali", sink_helper)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True,
                                     sanitizers=[{"name": "clean",
                                                  "match": "name"}])],
                          stats=stats)
            control = TS.scan(td, [_rule(inter=True)])
        self.assertEqual(out, [], "relation via helper must honor suppression")
        self.assertGreaterEqual(stats["sanitizer_passages"], 1)
        self.assertEqual(len(control), 1, control)

    def test_sanitizer_owner_scoping(self):
        other = _class("Lcom/example/app/Other;", """\
.method public static clean(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    return-object p0
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public viaSafe()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Safe;->clean(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method

.method public viaOther()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Other;->clean(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Safe.smali",
                         self._clean_tree())
            _write_smali(td, "smali/com/example/app/Other.smali", other)
            stats: dict = {}
            out = TS.scan(td, [
                _rule(inter=True,
                      sanitizers=[{"owner": "Lcom/example/app/Safe;",
                                   "name": "clean"}])], stats=stats)
        self.assertEqual(len(out), 1, out)
        self.assertIn("viaOther", out[0]["detail"]["method"])
        self.assertEqual(stats["sanitizer_passages"], 1)
        self.assertEqual(stats["summaries_built"], 2)

    def test_sanitizer_argument_indexes_semantics(self):
        comb = _class("Lcom/example/app/Comb;", """\
.method public static combine(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    return-object p1
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0, v0}, Lcom/example/app/Comb;->combine(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Comb.smali", comb)
            stats_a: dict = {}
            wrong_arg = TS.scan(td, [
                _rule(inter=True,
                      sanitizers=[{"name": "combine", "match": "name",
                                   "argument_indexes": [0]}])], stats=stats_a)
            stats_b: dict = {}
            right_arg = TS.scan(td, [
                _rule(inter=True,
                      sanitizers=[{"name": "combine", "match": "name",
                                   "argument_indexes": [1]}])], stats=stats_b)
        self.assertEqual(len(wrong_arg), 1,
                         "sanitizing arg 0 cannot clean a return from arg 1")
        self.assertEqual(stats_a["sanitizer_passages"], 0)
        self.assertEqual(right_arg, [], "the returned arg is sanitized")
        self.assertEqual(stats_b["sanitizer_passages"], 1)

    def test_unresolved_sanitizer_stays_unknown(self):
        main = MAIN_CALL_IDENTITY.replace("Lcom/example/app/Helper;->identity",
                                          "Lcom/example/app/Gone;->sanitize")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True,
                                     sanitizers=[{"name": "sanitize",
                                                  "match": "name"}])],
                          stats=stats)
        self.assertEqual(out, [], "unresolved sanitizer must not claim clean")
        self.assertEqual(stats["sanitizers_unverified"], 1)
        self.assertEqual(stats["unresolved_calls"], 0)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"])
        self.assertIn("interprocedural gaps", stage["reason"])

    def test_incomplete_sanitizer_summary_stays_unknown(self):
        bad = _class("Lcom/example/app/Bad;", """\
.method public static sanitize(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    iget v1, p0, Lcom/example/app/Bad;->f:I
    return-object p0
.end method
""")
        main = MAIN_CALL_IDENTITY.replace("Lcom/example/app/Helper;->identity",
                                          "Lcom/example/app/Bad;->sanitize")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Bad.smali", bad)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True,
                                     sanitizers=[{"name": "sanitize",
                                                  "match": "name"}])],
                          stats=stats)
        self.assertEqual(out, [])
        self.assertEqual(stats["sanitizers_unverified"], 1)

    def test_sanitizer_context_scoping(self):
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public js()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Safe;->clean(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method

.method public html()V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Safe;->clean(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p0, v0}, Lcom/example/app/Text;->setHtml(Ljava/lang/String;)V
    return-void
.end method
"""
        scoped_sinks = [{"name": "loadUrl", "match": "name", "context": "js"},
                        {"name": "setHtml", "match": "name", "context": "html"}]
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Safe.smali",
                         self._clean_tree())
            stats_a: dict = {}
            scoped = TS.scan(td, [
                _rule(inter=True, sinks=scoped_sinks,
                      sanitizers=[{"name": "clean", "match": "name",
                                   "contexts": ["html"]}])], stats=stats_a)
            stats_b: dict = {}
            plain = TS.scan(td, [
                _rule(inter=True,
                      sanitizers=[{"name": "clean", "match": "name",
                                   "contexts": ["html"]}])], stats=stats_b)
        self.assertEqual(len(scoped), 1, scoped)
        self.assertIn("js", scoped[0]["detail"]["method"])
        self.assertEqual(stats_a["sanitizer_passages"], 1,
                         "html-context sanitizer suppresses the html sink")
        self.assertEqual(len(plain), 1, plain)
        self.assertIn("js", plain[0]["detail"]["method"])
        self.assertEqual(stats_b["sanitizer_passages"], 0,
                         "scoped sanitizer must not vouch for uncontexted sinks")


class TestRecursionAndSanitizerSafety(unittest.TestCase):
    """Batch J P0: the two recursion conclusions stay distinct, and
    unresolved/incomplete calls are never silently cleaned by sanitizer
    processing."""

    def test_recursive_relation_finding_is_partial_never_clean(self):
        loop = _class("Lcom/example/app/Loop3;", """\
.method public static rec(Ljava/lang/String;)V
    .locals 1
    invoke-static {p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-static {p0}, Lcom/example/app/Loop3;->rec(Ljava/lang/String;)V
    return-void
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Loop3;->rec(Ljava/lang/String;)V
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Loop3.smali", loop)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(len(out), 1, out)
        det = out[0]["detail"]
        self.assertEqual(det["via"],
                         ["Lcom/example/app/Loop3;->rec(Ljava/lang/String;)V"])
        analysis = det["analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertIn("interprocedural summary propagation",
                      analysis["reason"])
        self.assertTrue(analysis["interprocedural"])
        self.assertGreaterEqual(stats["summaries_incomplete"], 1)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("incomplete summar", stage["reason"])

    def test_recursive_sanitizer_stays_unverified(self):
        rec = _class("Lcom/example/app/Rec;", """\
.method public static clean(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    invoke-static {p0}, Lcom/example/app/Rec;->clean(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
""")
        main = MAIN_CALL_IDENTITY.replace("Lcom/example/app/Helper;->identity",
                                          "Lcom/example/app/Rec;->clean")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Rec.smali", rec)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True,
                                     sanitizers=[{"name": "clean",
                                                  "match": "name"}])],
                          stats=stats)
        self.assertEqual(out, [], "recursive sanitizer must suppress nothing")
        # Two usages are counted: the call site in MainActivity and the
        # recursive method's own self-call; neither is ever trusted.
        self.assertEqual(stats["sanitizers_unverified"], 2)
        self.assertEqual(stats["sanitizer_passages"], 0)
        self.assertGreaterEqual(stats["summaries_incomplete"], 1)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("interprocedural gaps", stage["reason"])

    def test_sanitizer_then_unresolved_keeps_gap_visible(self):
        clean = _class("Lcom/example/app/Safe;", """\
.method public static clean(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    return-object p0
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Safe;->clean(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Gone;->xform(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Safe.smali", clean)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True,
                                     sanitizers=[{"name": "clean",
                                                  "match": "name"}])],
                          stats=stats)
        self.assertEqual(out, [], "no clean claim after an unresolved call")
        self.assertEqual(stats["unresolved_calls"], 1)
        self.assertEqual(stats["sanitizer_passages"], 0)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("interprocedural gaps", stage["reason"])

    def test_unresolved_then_sanitizer_keeps_gap_visible(self):
        clean = _class("Lcom/example/app/Safe;", """\
.method public static clean(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    return-object p0
.end method
""")
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Gone;->xform(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Lcom/example/app/Safe;->clean(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
""" + LOADURL + """
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Safe.smali", clean)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True,
                                     sanitizers=[{"name": "clean",
                                                  "match": "name"}])],
                          stats=stats)
        self.assertEqual(out, [], "sanitizer must not erase an unknown flow")
        self.assertEqual(stats["unresolved_calls"], 1)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"], stage)
        self.assertIn("interprocedural gaps", stage["reason"])


class TestStagesAndGates(unittest.TestCase):
    def test_stage_reports_interop_gaps_as_partial(self):
        for key, needle in (("unresolved_calls", "unresolved"),
                            ("sanitizers_unverified", "unverified sanitizer"),
                            ("summaries_incomplete", "incomplete summar"),
                            ("ambiguous_methods", "ambiguous")):
            with self.subTest(key=key):
                stage = _taint_stage({"methods_scanned": 1,
                                      "truncated_any": False, key: 1})
                self.assertFalse(stage["complete"], stage)
                self.assertIn("interprocedural gaps", stage["reason"])
                self.assertIn(needle, stage["reason"])

    def test_measured_zero_interop_counters_complete(self):
        stage = _taint_stage({"methods_scanned": 1, "truncated_any": False,
                              **{k: 0 for k in INTEROP_KEYS}})
        self.assertTrue(stage["complete"], stage)

    def test_fast_stats_report_zero_interop_counters(self):
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, MAIN_CALL_IDENTITY)
            _write_smali(td, "smali/com/example/app/Helper.smali",
                         HELPER_IDENTITY)
            stats: dict = {}
            TS.scan(td, [_rule(inter=False)], stats=stats)
        for key in INTEROP_KEYS:
            self.assertEqual(stats.get(key), 0, key)
        self.assertTrue(_taint_stage(stats)["complete"])

    def test_scope_interprocedural_variant(self):
        plain = TS.analysis_scope()
        self.assertFalse(plain["interprocedural"])
        inter = TS.analysis_scope(interprocedural=True)
        self.assertTrue(inter["interprocedural"])
        self.assertEqual(inter["kind"], TS.ANALYSIS_KIND)
        self.assertTrue(inter["control_flow_aware"])
        self.assertIn("interprocedural",
                      " ".join(inter["limitations"]).lower())

    def test_identity_requires_descriptor_match(self):
        main = MAIN_CALL_IDENTITY.replace(
            "Lcom/example/app/Helper;->identity(Ljava/lang/String;)"
            "Ljava/lang/String;",
            "Lcom/example/app/Helper;->identity()Ljava/lang/String;")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            _write_smali(td, "smali/com/example/app/Helper.smali",
                         HELPER_IDENTITY)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(out, [], "descriptor mismatch is not the same method")
        self.assertEqual(stats["unresolved_calls"], 1)
        self.assertEqual(stats["summaries_built"], 0)

    def test_duplicate_identity_is_ambiguous_and_untrusted(self):
        dup_a = _class("Lcom/example/app/Dup;", """\
.method public static identity(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    return-object p0
.end method
""")
        dup_b = _class("Lcom/example/app/Dup;", """\
.method public static identity(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    const-string v0, "safe"
    return-object v0
.end method
""")
        main = MAIN_CALL_IDENTITY.replace("Lcom/example/app/Helper;->identity",
                                          "Lcom/example/app/Dup;->identity")
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, "smali/com/example/app/a.smali", dup_a)
            _write_smali(td, "smali/com/example/app/b.smali", dup_b)
            _write_smali(td, MAIN_REL, main)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(out, [], "ambiguous identity must not be trusted")
        self.assertEqual(stats["ambiguous_methods"], 1)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"])
        self.assertIn("ambiguous", stage["reason"])

    def test_unknown_join_preserves_taint_across_call(self):
        main = """\
.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2
""" + INTENT_GET + """
    move-result-object v0
    if-eqz v0, :skip
    invoke-static {v0}, Lcom/example/app/Gone;->m(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    :skip
""" + LOADURL + """
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, main)
            stats: dict = {}
            out = TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(len(out), 1,
                         "T+UNKNOWN must stay tainted, never clean")
        self.assertEqual(stats["unresolved_calls"], 1)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"])
        self.assertIn("1 unresolved call(s)", stage["reason"])


class TestSchema(unittest.TestCase):
    def _validate(self, params):
        rule = R.Rule({"id": "AS-9300", "title": "t", "kind": "smali-taint",
                       "severity": "high", "params": params}, path="t.json")
        return R._validate_rule(rule, "t.json")

    def test_schema_accepts_interop_and_sanitizer_keys(self):
        errs, warns = self._validate({
            "sources": [{"name": "x"}],
            "sinks": [{"name": "loadUrl", "context": "js"}],
            "sanitizers": [{"name": "clean", "argument_indexes": [0],
                            "contexts": ["html"]}],
            "interprocedural": True,
        })
        self.assertEqual(errs, [])
        self.assertEqual(warns, [])

    def test_schema_rejects_bad_interop_and_sanitizer_params(self):
        bad_cases = (
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "interprocedural": "yes"}, "boolean"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "interprocedural": 1}, "boolean"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "sanitizers": "clean"}, "non-empty list"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "sanitizers": []}, "non-empty list"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "sanitizers": [{"name": "clean", "nope": 1}]}, "nope"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "sanitizers": [{"name": "clean", "contexts": []}]},
             "non-empty"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "sanitizers": [{"name": "clean", "contexts": [""]}]},
             "non-empty"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "sanitizers": [{"name": "clean", "contexts": "html"}]},
             "contexts"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "sanitizers": [{"name": "clean", "context": "html"}]},
             "context"),
            ({"sources": [{"name": "x"}], "sinks": [{"name": "m"}],
              "sanitizers": [{"name": "clean", "argument_indexes": [-1]}]},
             ">="),
            ({"sources": [{"name": "x"}],
              "sinks": [{"name": "m", "context": ""}]}, "context"),
            ({"sources": [{"name": "x"}],
              "sinks": [{"name": "m", "context": 5}]}, "context"),
            ({"sources": [{"name": "x", "context": "js"}],
              "sinks": [{"name": "m"}]}, "context"),
        )
        for params, needle in bad_cases:
            with self.subTest(params=params):
                errs, _ = self._validate(params)
                self.assertTrue(any(needle in e for e in errs),
                                f"no {needle!r} error in {errs}")

    def test_shipped_rules_opt_in_to_interprocedural(self):
        rules, errors = R.load_dir("rules")
        self.assertEqual(errors, [])
        by_id = {r.id: r for r in rules}
        self.assertIs(by_id["AS-0033"].params.get("interprocedural"), True)
        self.assertIs(by_id["AS-0034"].params.get("interprocedural"), True)


class TestCoverageCounters(unittest.TestCase):
    def test_classless_smali_file_is_counted_and_surfaced(self):
        with tempfile.TemporaryDirectory() as td:
            _write_smali(td, MAIN_REL, MAIN_CALL_IDENTITY)
            _write_smali(td, "smali/com/example/app/Helper.smali",
                         HELPER_IDENTITY)
            _write_smali(td, "smali/com/example/app/NoClass.smali",
                         ".super Ljava/lang/Object;\n")
            stats: dict = {}
            TS.scan(td, [_rule(inter=True)], stats=stats)
        self.assertEqual(stats["files_no_class"], 1)
        stage = _taint_stage(stats)
        self.assertFalse(stage["complete"])
        self.assertIn("class", stage["reason"].lower())


if __name__ == "__main__":
    unittest.main()
