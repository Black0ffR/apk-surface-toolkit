"""B3 regression tests. Synthetic rule fixtures only; no APK execution."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from triagekit import rules as R


def _write(tmp: str, name: str, obj) -> str:
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return p


VALID_TAINT = {
    "id": "AS-9001",
    "title": "Synthetic taint",
    "kind": "smali-taint",
    "severity": "high",
    "check": "smali_taint",
    "params": {"sources": ["getStringExtra"], "sinks": ["loadUrl"], "cap": 5},
}


class TestExistingCorpus(unittest.TestCase):
    def test_38_rules_load_cleanly(self):
        rules, errors = R.load_dir("rules")
        self.assertEqual(len(rules), 38, f"errors: {errors}")
        self.assertEqual(errors, [])
        ids = [r.id for r in rules]
        self.assertEqual(len(set(ids)), len(ids), "duplicate IDs in shipped corpus")

    def test_inventory_summary(self):
        inv = {}
        rules, errors = R.load_dir("rules", inventory=inv)
        self.assertEqual(inv["files_seen"], 38)
        self.assertEqual(inv["rules_loaded"], 38)
        self.assertEqual(inv["rules_rejected"], 0)
        self.assertEqual(inv["duplicate_ids"], [])
        self.assertEqual(inv["errors"], errors)

    def test_shipped_corpus_has_no_warnings(self):
        inv = {}
        rules, errors = R.load_dir("rules", inventory=inv)
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 38)
        self.assertEqual(inv["warnings"], [],
                         f"shipped rules must be warning-free: {inv['warnings']}")


class TestValidation(unittest.TestCase):
    def _load(self, files: dict) -> tuple:
        with tempfile.TemporaryDirectory() as td:
            for name, obj in files.items():
                _write(td, name, obj)
            inv = {}
            rules, errors = R.load_dir(td, inventory=inv)
            return rules, errors, inv

    def test_missing_fields_rejected(self):
        rules, errors, _ = self._load({"a.json": {"id": "AS-1", "kind": "regex"}})
        self.assertEqual(rules, [])
        self.assertTrue(any("missing" in e for e in errors))

    def test_bad_severity_rejected(self):
        bad = dict(VALID_TAINT, id="AS-9002", severity="urgent")
        rules, errors, _ = self._load({"a.json": bad})
        self.assertEqual(rules, [])
        self.assertTrue(any("severity" in e for e in errors))

    def test_unsupported_kind_rejected(self):
        bad = dict(VALID_TAINT, id="AS-9003", kind="native-flow")
        rules, errors, _ = self._load({"a.json": bad})
        self.assertEqual(rules, [])
        self.assertTrue(any("unsupported kind" in e for e in errors))

    def test_unsupported_check_rejected(self):
        bad = dict(VALID_TAINT, id="AS-9004", check="no_such_check")
        rules, errors, _ = self._load({"a.json": bad})
        self.assertEqual(rules, [])
        self.assertTrue(any("unsupported check" in e for e in errors))

    def test_bad_regex_rejected(self):
        bad = {
            "id": "AS-9005", "title": "x", "kind": "regex", "severity": "low",
            "params": {"pattern": "([unclosed"},
        }
        rules, errors, _ = self._load({"a.json": bad})
        self.assertEqual(rules, [])
        self.assertTrue(any("regex" in e.lower() for e in errors))

    def test_missing_regex_pattern_rejected(self):
        bad = {"id": "AS-9006", "title": "x", "kind": "regex", "severity": "low", "params": {}}
        rules, errors, _ = self._load({"a.json": bad})
        self.assertEqual(rules, [])
        self.assertTrue(any("pattern" in e for e in errors))

    def test_invalid_sources_sinks_rejected(self):
        for params in (
            {"sources": [], "sinks": ["loadUrl"]},
            {"sources": ["getStringExtra"], "sinks": ["ok\nevil"]},
            {"sources": [123], "sinks": ["loadUrl"]},
        ):
            bad = dict(VALID_TAINT, id="AS-9007", params=params)
            rules, errors, _ = self._load({"a.json": bad})
            self.assertEqual(rules, [], f"accepted {params}")
            self.assertTrue(errors, f"no error for {params}")

    def test_invalid_cap_rejected(self):
        for cap in (0, -3, "many", [15]):
            bad = dict(VALID_TAINT, id="AS-9008",
                       params={"sources": ["a"], "sinks": ["b"], "cap": cap})
            rules, errors, _ = self._load({"a.json": bad})
            self.assertEqual(rules, [], f"accepted cap={cap!r}")

    def test_duplicate_ids_reported_first_wins(self):
        a = dict(VALID_TAINT, id="AS-DUP")
        b = dict(VALID_TAINT, id="AS-DUP", title="Second copy")
        rules, errors, inv = self._load({"a.json": a, "b.json": b})
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].title, "Synthetic taint")
        self.assertTrue(any("duplicate" in e.lower() for e in errors))
        self.assertIn("AS-DUP", inv["duplicate_ids"])

    def test_broken_file_does_not_abort_others(self):
        with tempfile.TemporaryDirectory() as td:
            _write(td, "good.json", VALID_TAINT)
            with open(os.path.join(td, "bad.json"), "w", encoding="utf-8") as f:
                f.write("{not json")
            rules, errors = R.load_dir(td)
            self.assertEqual(len(rules), 1)
            self.assertTrue(any("bad.json" in e for e in errors))

    def test_unexpected_json_types_rejected(self):
        rules, errors, _ = self._load({"a.json": ["not", "a", "mapping"]})
        self.assertEqual(rules, [])
        self.assertTrue(errors)


class TestNumericsAndWarnings(unittest.TestCase):
    def _load(self, files: dict) -> tuple:
        import tempfile as _tf
        with _tf.TemporaryDirectory() as td:
            for name, obj in files.items():
                p = os.path.join(td, name)
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(obj, f)
            inv: dict = {}
            rules, errors = R.load_dir(td, inventory=inv)
            return rules, errors, inv

    def test_booleans_rejected_for_numerics(self):
        bad = dict(VALID_TAINT, id="AS-9101",
                   params={"sources": ["a"], "sinks": ["b"], "cap": True})
        rules, errors, _ = self._load({"a.json": bad})
        self.assertEqual(rules, [])
        ent = {"id": "AS-9102", "title": "x", "kind": "regex", "severity": "low",
               "params": {"pattern": "abc", "entropy_min": True}}
        rules, errors, _ = self._load({"a.json": ent})
        self.assertEqual(rules, [])
        self.assertTrue(any("entropy_min" in e for e in errors))

    def test_non_finite_rejected(self):
        for bad_val in (float("nan"), float("inf"), float("-inf")):
            ent = {"id": "AS-9103", "title": "x", "kind": "regex", "severity": "low",
                   "params": {"pattern": "abc", "entropy_min": bad_val}}
            rules, errors, _ = self._load({"a.json": ent})
            self.assertEqual(rules, [], f"accepted entropy_min={bad_val!r}")
            self.assertTrue(errors)

    def test_entropy_range_enforced(self):
        ent = {"id": "AS-9104", "title": "x", "kind": "regex", "severity": "low",
               "params": {"pattern": "abc", "entropy_min": -1.5}}
        rules, errors, _ = self._load({"a.json": ent})
        self.assertEqual(rules, [])

    def test_unknown_params_warn_but_load(self):
        good = dict(VALID_TAINT, id="AS-9105")
        good["params"] = dict(good["params"], future_option=True)
        rules, errors, inv = self._load({"a.json": good})
        self.assertEqual(len(rules), 1)
        self.assertEqual(errors, [])
        self.assertTrue(any("future_option" in w for w in inv.get("warnings", [])),
                        f"no warning: {inv}")

    def test_inventory_separates_rule_and_file_failures(self):
        import tempfile as _tf
        with _tf.TemporaryDirectory() as td:
            with open(os.path.join(td, "good.json"), "w", encoding="utf-8") as f:
                json.dump(VALID_TAINT, f)
            bad = dict(VALID_TAINT, id="AS-9106", kind="nope")
            with open(os.path.join(td, "badrule.json"), "w", encoding="utf-8") as f:
                json.dump(bad, f)
            with open(os.path.join(td, "broken.json"), "w", encoding="utf-8") as f:
                f.write("{not json")
            inv: dict = {}
            rules, errors = R.load_dir(td, inventory=inv)
            self.assertEqual(len(rules), 1)
            self.assertEqual(inv["rules_rejected"], 1)
            self.assertEqual(inv["files_failed"], 1)
            self.assertIn("warnings", inv)


class TestTaintMatcherSchema(unittest.TestCase):
    def _load(self, params, extra_files=None) -> tuple:
        obj = dict(VALID_TAINT, id="AS-9200", params=params)
        files = {"a.json": obj}
        files.update(extra_files or {})
        with tempfile.TemporaryDirectory() as td:
            for name, o in files.items():
                _write(td, name, o)
            inv = {}
            rules, errors = R.load_dir(td, inventory=inv)
            return rules, errors, inv

    def test_structured_entry_loads_cleanly(self):
        params = {
            "sources": [{"owner": "Landroid/content/Intent;", "name": "getStringExtra"}],
            "sinks": [{"owner": "Landroid/webkit/WebView;", "name": "loadUrl",
                       "match": "owner-name"}],
        }
        rules, errors, inv = self._load(params)
        self.assertEqual(errors, [])
        self.assertEqual(inv["warnings"], [])
        self.assertEqual(len(rules), 1)

    def test_owner_implies_owner_name_mode_by_default(self):
        params = {"sources": [{"owner": "Lx/A;", "name": "m"}],
                  "sinks": [{"name": "loadUrl"}]}
        rules, errors, _ = self._load(params)
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 1)

    def test_name_mode_with_owner_rejected(self):
        params = {"sources": [{"name": "x"}],
                  "sinks": [{"owner": "Lx/A;", "name": "m", "match": "name"}]}
        rules, errors, _ = self._load(params)
        self.assertEqual(rules, [])
        self.assertTrue(any("owner" in e for e in errors), errors)

    def test_owner_name_mode_without_owner_rejected(self):
        params = {"sources": [{"name": "x"}],
                  "sinks": [{"name": "m", "match": "owner-name"}]}
        rules, errors, _ = self._load(params)
        self.assertEqual(rules, [])
        self.assertTrue(any("requires an owner" in e for e in errors), errors)

    def test_unknown_entry_key_rejected(self):
        params = {"sources": [{"name": "x"}], "sinks": [{"name": "m", "nope": 1}]}
        rules, errors, _ = self._load(params)
        self.assertEqual(rules, [])
        self.assertTrue(any("nope" in e for e in errors), errors)

    def test_missing_or_bad_name_rejected(self):
        for entry in ({"owner": "Lx/A;"}, {"name": ""}, {"name": 5}):
            with self.subTest(entry=entry):
                params = {"sources": [{"name": "x"}], "sinks": [entry]}
                rules, errors, _ = self._load(params)
                self.assertEqual(rules, [], f"accepted {entry}")
                self.assertTrue(errors)

    def test_bad_match_mode_rejected(self):
        params = {"sources": [{"name": "x"}],
                  "sinks": [{"name": "m", "match": "glob"}]}
        rules, errors, _ = self._load(params)
        self.assertEqual(rules, [])
        self.assertTrue(any("match" in e for e in errors), errors)

    def test_regex_mode_validation(self):
        good = {"sources": [{"name": "x"}],
                "sinks": [{"name": "load.*", "match": "regex"}]}
        rules, errors, _ = self._load(good)
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 1)
        for bad in ("([unclosed", "(a+)+$", "a" * 501):
            with self.subTest(bad=bad[:20]):
                params = {"sources": [{"name": "x"}],
                          "sinks": [{"name": bad, "match": "regex"}]}
                rules, errors, _ = self._load(params)
                self.assertEqual(rules, [], f"accepted {bad[:20]!r}")
                self.assertTrue(errors)

    def test_argument_indexes_sinks_only_and_typed(self):
        good = {"sources": [{"name": "x"}],
                "sinks": [{"name": "loadUrl", "argument_indexes": [0, 1]}]}
        rules, errors, _ = self._load(good)
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 1)
        bad_cases = (
            ({"sources": [{"name": "x", "argument_indexes": [0]}],
              "sinks": [{"name": "m"}]}, "only valid for sinks"),
            ({"sources": [{"name": "x"}],
              "sinks": [{"name": "m", "argument_indexes": []}]}, "non-empty"),
            ({"sources": [{"name": "x"}],
              "sinks": [{"name": "m", "argument_indexes": [-1]}]}, ">="),
            ({"sources": [{"name": "x"}],
              "sinks": [{"name": "m", "argument_indexes": [True]}]}, ">="),
            ({"sources": [{"name": "x"}],
              "sinks": [{"name": "m", "argument_indexes": ["0"]}]}, ">="),
        )
        for params, needle in bad_cases:
            with self.subTest(params=params):
                rules, errors, _ = self._load(params)
                self.assertEqual(rules, [], f"accepted {params}")
                self.assertTrue(any(needle in e for e in errors), errors)

    def test_legacy_string_warns_but_loads(self):
        params = {"sources": ["getStringExtra", {"name": "getData"}],
                  "sinks": ["loadUrl"]}
        rules, errors, inv = self._load(params)
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 1)
        self.assertEqual(len(inv["warnings"]), 2, inv["warnings"])
        self.assertTrue(all("legacy" in w for w in inv["warnings"]), inv["warnings"])
        self.assertFalse(any("getData" in w for w in inv["warnings"]), inv["warnings"])

    def test_malformed_entry_does_not_block_other_rules(self):
        bad = dict(VALID_TAINT, id="AS-9201",
                   params={"sources": [{"nope": 1}], "sinks": ["loadUrl"]})
        good = dict(VALID_TAINT, id="AS-9202",
                    params={"sources": [{"name": "getStringExtra"}],
                            "sinks": [{"name": "loadUrl"}]})
        rules, errors, _ = self._load({}, extra_files={"bad.json": bad, "good.json": good})
        self.assertEqual([r.id for r in rules], ["AS-9202"])
        self.assertTrue(any("AS-9201" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
