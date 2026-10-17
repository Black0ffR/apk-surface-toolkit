"""B1 regression tests. Synthetic smali only; no APK execution."""
from __future__ import annotations

import os
import tempfile
import unittest

from triagekit import callgraph as CG
from triagekit import rules as R


def _chain_tree(root: str, n: int = 20) -> str:
    """One exported App class fanning out to M1..Mn, each calling loadUrl.

    Fan-out (not a linear chain) guarantees the sink stays reachable even
    when the traversal limit truncates the closure: the first methods in
    the closure already contain callers of the sink.
    """
    d = os.path.join(root, "smali", "com", "example")
    os.makedirs(d, exist_ok=True)
    app_calls = "".join(
        f"    invoke-virtual {{p0}}, Lcom/example/Chain;->m{i}()V\n" for i in range(1, n + 1)
    )
    app = (
        ".class public Lcom/example/App;\n.super Ljava/lang/Object;\n\n"
        ".method public entry()V\n    .locals 1\n" + app_calls + "    return-void\n.end method\n"
    )
    with open(os.path.join(d, "App.smali"), "w", encoding="utf-8") as f:
        f.write(app)
    body = [".class public Lcom/example/Chain;", ".super Ljava/lang/Object;", ""]
    for i in range(1, n + 1):
        body.append(
            ".method public m{i}()V\n    .locals 1\n"
            "    invoke-virtual {{p0, v0}}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n"
            "    return-void\n.end method\n".format(i=i)
        )
    with open(os.path.join(d, "Chain.smali"), "w", encoding="utf-8") as f:
        f.write("\n".join(body) + "\n")
    return os.path.join(root, "smali")


def _rule(**params):
    raw = {
        "id": "AS-0038",
        "title": "Exported entry reaches a sensitive sink",
        "kind": "reachability",
        "severity": "high",
        "params": {"sinks": ["loadUrl"], "cap": 15, **params},
        "recommendation": "confirm with runtime probe",
    }
    return R.Rule(raw, path="synthetic")


def _man():
    return {"components": [{"name": "com.example.App", "type": "activity", "exported": True}]}


class TestTraversalTruncation(unittest.TestCase):
    def test_small_graph_reports_complete(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _chain_tree(td, n=3)
            out = CG.check_reachability([_rule()], decoded, _man())
        self.assertTrue(out, "chain sink should be reachable")
        for f in out:
            analysis = f.get("detail", {}).get("analysis", {})
            self.assertEqual(analysis.get("status"), "complete")
            self.assertFalse(analysis.get("truncated"))
            self.assertIn("limit", analysis)

    def test_truncated_graph_marks_findings_partial(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _chain_tree(td, n=20)
            out = CG.check_reachability([_rule(reach_limit=5)], decoded, _man())
        self.assertTrue(out, "sink reachable; findings must exist even when truncated")
        self.assertTrue(
            any(f.get("detail", {}).get("analysis", {}).get("truncated") for f in out),
            f"truncation not propagated: {out}",
        )
        for f in out:
            self.assertEqual(f["detail"]["analysis"]["status"], "partial")
            self.assertEqual(f["detail"]["analysis"]["limit"], 5)

    def test_no_hit_truncated_is_inconclusive_not_clean(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _chain_tree(td, n=20)
            rule = _rule(reach_limit=5)
            rule.params["sinks"] = ["definitelyNotASinkXYZ"]
            out = CG.check_reachability([rule], decoded, _man())
        # A truncated graph with no hit must NOT look like a clean negative.
        self.assertEqual(len(out), 1, f"expected one coverage record, got {out}")
        cov = out[0]
        self.assertEqual(cov["detail"].get("coverage"), "inconclusive-no-hit-truncated")
        self.assertEqual(cov["detail"]["analysis"]["status"], "partial")
        self.assertTrue(cov["detail"]["analysis"]["truncated"])
        self.assertIn("inconclusive", cov["evidence"].lower())
        self.assertIn("not", cov["evidence"].lower())

class TestParseCoverage(unittest.TestCase):
    def _tree_with(self, root: str, extra_lines: list[str], broken: bool = False) -> str:
        d = os.path.join(root, "smali", "com", "example")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "App.smali"), "w", encoding="utf-8") as f:
            f.write(".class public Lcom/example/App;\n.super Ljava/lang/Object;\n\n"
                    ".method public entry()V\n    .locals 3\n"
                    "    invoke-virtual {p0}, Lcom/example/Chain;->m1()V\n"
                    + "".join(extra_lines) +
                    "    return-void\n.end method\n")
        with open(os.path.join(d, "Chain.smali"), "w", encoding="utf-8") as f:
            f.write(".class public Lcom/example/Chain;\n.super Ljava/lang/Object;\n\n"
                    ".method public m1()V\n    .locals 1\n"
                    "    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n"
                    "    return-void\n.end method\n")
            if broken:
                f.write("\n.method public brokenmethod\n    return-void\n.end method\n")
        return os.path.join(root, "smali")

    def test_unparsed_invoke_forces_partial(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = self._tree_with(td, ["    invoke-direct {v0}, weird-target-without-arrow\n"])
            cov: dict = {}
            out = CG.check_reachability([_rule()], decoded, _man(), coverage=cov)
        stats = cov.get("build_stats", {})
        self.assertGreaterEqual(stats.get("unparsed_invokes", 0), 1)
        self.assertTrue(out, "supported edges must still resolve (fallback preserved)")
        for f in out:
            self.assertIn("parse_coverage", f.get("detail", {}))
            self.assertEqual(f["detail"]["parse_coverage"].get("unparsed_invokes"), 1)
            self.assertEqual(f["detail"]["analysis"]["status"], "partial")

    def test_malformed_method_forces_partial(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = self._tree_with(td, [], broken=True)
            cov = {}
            out = CG.check_reachability([_rule()], decoded, _man(), coverage=cov)
        self.assertGreaterEqual(cov.get("build_stats", {}).get("malformed_methods", 0), 1)
        self.assertTrue(out)
        self.assertTrue(all(f["detail"]["analysis"]["status"] == "partial" for f in out))

    def test_polymorphic_fallback_preserved_but_approximate(self):
        line = ("    invoke-polymorphic {v0, v1}, Ljava/lang/Object;->wait:()V, "
                "(I)V, Lmethodhandle;\n")
        with tempfile.TemporaryDirectory() as td:
            decoded = self._tree_with(td, [line])
            cov: dict = {}
            stats: dict = {}
            con = CG.build(decoded, stats=stats)
            try:
                targets = [r[0] for r in con.execute(
                    "SELECT target FROM instructions WHERE kind='call'").fetchall()]
            finally:
                con.close()
            out = CG.check_reachability([_rule()], decoded, _man(), coverage=cov)
        self.assertGreaterEqual(stats.get("calls_legacy_fallback", 0), 1)
        # Fallback edge keeps the stripped target (behavior preserved) ...
        self.assertTrue(any(t == "Ljava/lang/Object;->wait:" for t in targets), targets)
        # ... but the result is approximate, never apparently complete.
        self.assertTrue(out)
        self.assertTrue(all(f["detail"]["analysis"]["status"] == "partial" for f in out))

    def test_clean_tree_reports_parse_counts(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = self._tree_with(td, [])
            cov = {}
            out = CG.check_reachability([_rule()], decoded, _man(), coverage=cov)
        stats = cov.get("build_stats", {})
        self.assertEqual(stats.get("unparsed_invokes", 0), 0)
        self.assertEqual(stats.get("malformed_methods", 0), 0)
        self.assertTrue(out)
        self.assertTrue(all(f["detail"]["analysis"]["status"] == "complete" for f in out))

    def test_reachable_limit_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = _chain_tree(td, n=20)
            con = CG.build(decoded)
            try:
                seeds = [s for (s,) in con.execute("SELECT sig FROM methods WHERE cls='Lcom/example/App;'").fetchall()]
                a = CG.reachable(con, seeds, limit=5)
                b = CG.reachable(con, seeds, limit=5)
            finally:
                con.close()
        self.assertTrue(a["truncated"])
        self.assertEqual(a, b)


class TestReadCapCoverage(unittest.TestCase):
    def _tree(self, root: str, big: bool) -> str:
        d = os.path.join(root, "smali", "com", "example")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "App.smali"), "w", encoding="utf-8") as f:
            f.write(".class public Lcom/example/App;\n.super Ljava/lang/Object;\n\n"
                    ".method public entry()V\n    .locals 1\n"
                    "    invoke-virtual {p0}, Lcom/example/Big;->big()V\n"
                    "    return-void\n.end method\n")
        body = (".class public Lcom/example/Big;\n.super Ljava/lang/Object;\n\n"
                ".method public big()V\n    .locals 1\n"
                "    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n"
                "    return-void\n.end method\n")
        if big:
            body += "".join("    # pad %06d\n" % i for i in range(40000))
        with open(os.path.join(d, "Big.smali"), "w", encoding="utf-8") as f:
            f.write(body)
        return os.path.join(root, "smali")

    def test_file_over_read_cap_is_counted_and_forces_partial(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = self._tree(td, big=True)
            cov: dict = {}
            out = CG.check_reachability([_rule()], decoded, _man(), coverage=cov)
        stats = cov.get("build_stats", {})
        self.assertEqual(stats.get("files_truncated"), 1)
        self.assertTrue(out, "readable portion still produces findings")
        for f in out:
            self.assertEqual(f["detail"]["parse_coverage"].get("files_truncated"), 1)
            self.assertEqual(f["detail"]["analysis"]["status"], "partial")
            self.assertIn("truncat", f["detail"]["analysis"]["reason"].lower())

    def test_file_under_read_cap_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            decoded = self._tree(td, big=False)
            cov = {}
            out = CG.check_reachability([_rule()], decoded, _man(), coverage=cov)
        stats = cov.get("build_stats", {})
        self.assertEqual(stats.get("files_truncated", 0), 0)
        self.assertTrue(out)
        for f in out:
            self.assertEqual(f["detail"]["analysis"]["status"], "complete",
                             f["detail"]["analysis"])


if __name__ == "__main__":
    unittest.main()
