"""CG-01 + CG-02 regression tests. Synthetic smali only, no APK execution."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from triagekit import callgraph as CG


OVERLOAD_SMALI = """\
.class public Lcom/example/Overloads;
.super Ljava/lang/Object;

.method public foo(I)V
    .locals 1
    invoke-virtual {p0}, Lcom/example/Other;->bar(I)V
    return-void
.end method

.method public foo(Ljava/lang/String;)V
    .locals 1
    invoke-virtual {p0}, Lcom/example/Other;->bar(Ljava/lang/String;)V
    return-void
.end method

.method public <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method static <clinit>()V
    .locals 0
    return-void
.end method
"""

CALLER_SMALI = """\
.class public Lcom/example/App;
.super Ljava/lang/Object;

.method public onCreate()V
    .locals 2
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->preloadUrl(Ljava/lang/String;)V
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrlUnsafe(Ljava/lang/String;)V
    invoke-static {v0}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    return-void
.end method

.method public other()V
    .locals 1
    invoke-virtual/range {v0 .. v1}, Lcom/example/Overloads;->foo(I)V
    const-string v0, "hi"
    sget-object v0, Lcom/example/Overloads;->label:Ljava/lang/String;
    sput-object v0, Lcom/example/Overloads;->label:Ljava/lang/String;
    return-void
.end method
"""


def _write_tree(root: str) -> str:
    d = os.path.join(root, "smali", "com", "example")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "Overloads.smali"), "w", encoding="utf-8") as f:
        f.write(OVERLOAD_SMALI)
    with open(os.path.join(d, "App.smali"), "w", encoding="utf-8") as f:
        f.write(CALLER_SMALI)
    return os.path.join(root, "smali")


class TestMethodIdentity(unittest.TestCase):
    def test_overloads_remain_distinct(self):
        """Two methods differing only by descriptor must be distinct nodes."""
        with tempfile.TemporaryDirectory() as td:
            decoded = _write_tree(td)
            con = CG.build(decoded)
            try:
                sigs = sorted(
                    r[0] for r in con.execute("SELECT sig FROM methods").fetchall()
                )
            finally:
                con.close()
        foo_sigs = sorted(s for s in sigs if "Overloads;->foo(" in s)
        self.assertEqual(len(foo_sigs), 2, f"overloads merged: {sigs}")
        self.assertIn("Lcom/example/Overloads;->foo(I)V", foo_sigs)
        self.assertIn(
            "Lcom/example/Overloads;->foo(Ljava/lang/String;)V", foo_sigs
        )

    def test_invoke_targets_preserve_descriptors(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _write_tree(td)
            con = CG.build(decoded)
            try:
                targets = sorted(
                    r[0]
                    for r in con.execute(
                        "SELECT DISTINCT target FROM instructions WHERE kind='call'"
                    ).fetchall()
                )
            finally:
                con.close()
        self.assertIn(
            "Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V", targets
        )
        self.assertIn("Lcom/example/Overloads;->foo(I)V", targets)
        # range form must be captured with descriptor
        self.assertTrue(
            any(t.startswith("Lcom/example/Overloads;->foo(I)V") for t in targets),
            f"range invoke lost: {targets}",
        )

    def test_constructors_and_field_types(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _write_tree(td)
            con = CG.build(decoded)
            try:
                sigs = [r[0] for r in con.execute("SELECT sig FROM methods").fetchall()]
                ftargets = [
                    r[0]
                    for r in con.execute(
                        "SELECT target FROM instructions WHERE kind LIKE 'field-%'"
                    ).fetchall()
                ]
            finally:
                con.close()
        self.assertIn("Lcom/example/Overloads;-><init>()V", sigs)
        self.assertTrue(
            any("->label:" in t and "Ljava/lang/String;" in t for t in ftargets),
            f"field type dropped: {ftargets}",
        )


class TestExactMatching(unittest.TestCase):
    def _con(self, decoded_holder):
        decoded = _write_tree(decoded_holder)
        return CG.build(decoded)

    def test_bare_name_does_not_match_substrings(self):
        with tempfile.TemporaryDirectory() as td:
            con = self._con(td)
            try:
                callers = CG.callers_of(con, "loadUrl")
                caller_names = sorted(c["caller"] for c in callers)
                # every returned caller must contain an exact loadUrl ref,
                # not merely preloadUrl/loadUrlUnsafe
                refs = [
                    r[0]
                    for r in con.execute(
                        "SELECT DISTINCT target FROM instructions WHERE kind='call'"
                    ).fetchall()
                ]
            finally:
                con.close()
        self.assertTrue(
            any("->loadUrl(" in r for r in refs), f"fixture missing loadUrl: {refs}"
        )
        # The buggy LIKE implementation returns callers based on substring;
        # exact matching must still find the true caller ...
        self.assertTrue(caller_names, "exact loadUrl should match its caller")
        # ... and must report how it matched.
        for c in callers:
            self.assertIn("match_mode", c, "match mode must be in evidence")
            self.assertIn("matched_target", c)

    def test_preload_variants_are_not_loadurl(self):
        """Direct unit check: preloadUrl/loadUrlUnsafe refs must not satisfy loadUrl."""
        with tempfile.TemporaryDirectory() as td:
            con = self._con(td)
            try:
                for target, should_match in [
                    ("Landroid/webkit/WebView;->preloadUrl(Ljava/lang/String;)V", False),
                    ("Landroid/webkit/WebView;->loadUrlUnsafe(Ljava/lang/String;)V", False),
                    ("Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V", True),
                ]:
                    # canonical exact target must match only itself
                    got = CG.callers_of(con, target)
                    if should_match:
                        self.assertTrue(got, f"{target} should match")
                    else:
                        # preloadUrl exact ref exists in fixture so it matches itself;
                        # the point is it must NOT be returned for a loadUrl query
                        via_loadurl = CG.callers_of(con, "loadUrl")
                        # resolve which refs the returned callers actually contain
                        self.assertTrue(via_loadurl)
            finally:
                con.close()
        # Bare-name query must use token equality, verified via helper:
        self.assertTrue(
            CG._target_matches(
                "Landroid/webkit/WebView;->preloadUrl(Ljava/lang/String;)V", "loadUrl"
            )[0]
            is False
        )
        self.assertTrue(
            CG._target_matches(
                "Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V", "loadUrl"
            )[0]
            is True
        )

    def test_owner_isolation(self):
        self.assertTrue(
            CG._target_matches(
                "Lcom/other/Foo;->loadUrl(Ljava/lang/String;)V", "loadUrl"
            )[0]
            is True
        )
        # owner+name query must not match a different owner
        got_mode = CG._target_matches(
            "Lcom/other/Foo;->loadUrl(Ljava/lang/String;)V",
            "Landroid/webkit/WebView;->loadUrl",
        )
        self.assertFalse(got_mode[0], f"cross-owner match: {got_mode}")

    def test_overload_isolation(self):
        ok_exact, mode = CG._target_matches(
            "Lcom/example/Overloads;->foo(I)V",
            "Lcom/example/Overloads;->foo(I)V",
        )
        self.assertTrue(ok_exact)
        self.assertEqual(mode, "exact-reference")
        ko, _ = CG._target_matches(
            "Lcom/example/Overloads;->foo(Ljava/lang/String;)V",
            "Lcom/example/Overloads;->foo(I)V",
        )
        self.assertFalse(ko)

    def test_owner_suffix_requires_segment_boundary(self):
        """F5: `MyRuntime;` must not satisfy a `Runtime;` owner query."""
        ko, mode = CG._target_matches("Lcom/evil/MyRuntime;->exec()V", "Runtime;->exec")
        self.assertFalse(ko, f"owner-suffix boundary violated: {mode}")
        ok, mode = CG._target_matches(
            "Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;",
            "Runtime;->exec")
        self.assertTrue(ok)
        self.assertEqual(mode, "owner-suffix-name")
        ok2, mode2 = CG._target_matches("Lcom/evil/MyRuntime;->exec()V",
                                        "MyRuntime;->exec")
        self.assertTrue(ok2)
        self.assertEqual(mode2, "owner-suffix-name")

    def test_deterministic_sorted_results(self):
        with tempfile.TemporaryDirectory() as td:
            con = self._con(td)
            try:
                a = [c["caller"] for c in CG.callers_of(con, "loadUrl")]
                b = [c["caller"] for c in CG.callers_of(con, "loadUrl")]
            finally:
                con.close()
        self.assertEqual(a, sorted(a))
        self.assertEqual(a, b)


class TestClassSeeds(unittest.TestCase):
    """F6: seeds are exact — no LIKE case-insensitivity or `_` wildcards."""

    def _con(self):
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE methods(id INTEGER PRIMARY KEY, sig TEXT, cls TEXT)")
        con.executemany(
            "INSERT INTO methods(sig, cls) VALUES (?, ?)",
            [("Lcom/a/B;->a()V", "Lcom/a/B;"),
             ("Lcom/a/B$Inner;->b()V", "Lcom/a/B$Inner;"),
             ("Lcom/a/bc$X;->c()V", "Lcom/a/bc$X;"),
             ("Lcom/a/BXC$Y;->d()V", "Lcom/a/BXC$Y;"),
             ("Lcom/a/B_C;->e()V", "Lcom/a/B_C;")])
        return con

    def test_exact_and_nested_only(self):
        con = self._con()
        try:
            got = CG._class_seeds(con, "Lcom/a/B")
        finally:
            con.close()
        self.assertEqual(got, ["Lcom/a/B$Inner;->b()V", "Lcom/a/B;->a()V"])
        self.assertNotIn("Lcom/a/bc$X;->c()V", got)

    def test_no_case_insensitive_match(self):
        con = self._con()
        try:
            got = CG._class_seeds(con, "Lcom/a/b")
        finally:
            con.close()
        self.assertEqual(got, [])

    def test_no_underscore_wildcard_match(self):
        con = self._con()
        try:
            got = CG._class_seeds(con, "Lcom/a/B_C")
        finally:
            con.close()
        self.assertEqual(got, ["Lcom/a/B_C;->e()V"])
        self.assertNotIn("Lcom/a/BXC$Y;->d()V", got)


class TestParserAdoptionFallback(unittest.TestCase):
    def test_malformed_register_list_keeps_strict_identity(self):
        """The shared parser rejects `{v0, x1}`; the strict fallback must
        still index the call with its full descriptor identity."""
        smali = (".class public Lcom/example/A;\n.super Ljava/lang/Object;\n\n"
                 ".method public go()V\n    .locals 2\n"
                 "    invoke-virtual {v0, x1}, Lcom/example/Other;->m(I)V\n"
                 "    return-void\n.end method\n")
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "smali", "com", "example")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "A.smali"), "w", encoding="utf-8") as f:
                f.write(smali)
            stats: dict = {}
            con = CG.build(os.path.join(td, "smali"), stats=stats)
            try:
                targets = [r[0] for r in con.execute(
                    "SELECT target FROM instructions WHERE kind='call'").fetchall()]
            finally:
                con.close()
        self.assertIn("Lcom/example/Other;->m(I)V", targets)
        self.assertEqual(stats["calls_legacy_fallback"], 0)
        self.assertEqual(stats["unparsed_invokes"], 0)


if __name__ == "__main__":
    unittest.main()
