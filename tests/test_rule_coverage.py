"""RL-01/TEST-01: fixture-driven coverage for every shipped rule.

Each shipped rule (rules/AS-*.json) is loaded from the real corpus and run
through its real analyzer path against positive/negative fixtures:

  manifest     -> analyzer.check_manifest (manifest parsed via manifest.parse,
                  nsc / file-paths / backup-rules read from the fixture tree)
  regex        -> analyzer.check_regex
  smali-taint  -> taint_smali.scan
  reachability -> callgraph.check_reachability

The test-to-rule mapping lives in tests/rule_fixture_map.py; a shipped rule
without a mapping entry (or UNTESTED record with a reason) fails the audit
tests here. No APK execution; synthetic decoded trees only.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile

from triagekit import analyzer as AN
from triagekit import callgraph as CG
from triagekit import manifest as MF
from triagekit import rules as R
from triagekit import taint_smali as TS

try:
    from tests.rule_fixture_map import RULE_CASES, UNTESTED
except ImportError:  # pragma: no cover - direct discovery from inside tests/
    from rule_fixture_map import RULE_CASES, UNTESTED

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
RULES_DIR = os.path.join(ROOT, "rules")

SHIPPED, LOAD_ERRORS = R.load_dir(RULES_DIR)
BY_ID = {r.id: r for r in SHIPPED}
PLATFORM = AN.load_platform_perms(os.path.join(RULES_DIR, "platform_permissions.txt"))


def fixture(*parts: str) -> str:
    return os.path.join(FIXTURES, *parts)


def case_dir(rel: str) -> str:
    """Mapping-relative fixture dir (mapping dirs are relative to decoded/)."""
    return os.path.join(FIXTURES, "decoded", rel)


def _sig(directory: str):
    path = os.path.join(directory, "sig.json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def run_rule(rule: R.Rule, directory: str) -> list[dict]:
    """Exercise one rule through the analyzer path for its kind."""
    if rule.kind == "manifest":
        man = MF.parse(os.path.join(directory, "AndroidManifest.xml"))
        return AN.check_manifest(
            [rule], man,
            MF.read_network_security_config(directory),
            PLATFORM,
            MF.read_file_provider_paths(directory),
            _sig(directory),
            MF.read_backup_rules(directory, man),
        )
    if rule.kind == "regex":
        return AN.check_regex([rule], directory)
    if rule.kind == "smali-taint":
        return TS.scan(directory, [rule])
    if rule.kind == "reachability":
        man = MF.parse(os.path.join(directory, "AndroidManifest.xml"))
        return CG.check_reachability([rule], directory, man)
    raise AssertionError(f"no fixture runner for rule kind {rule.kind!r}")


def _subset(sub, sup) -> bool:
    if isinstance(sub, dict):
        return isinstance(sup, dict) and all(
            k in sup and _subset(v, sup[k]) for k, v in sub.items())
    if isinstance(sub, list):
        return (isinstance(sup, list) and len(sub) == len(sup)
                and all(_subset(a, b) for a, b in zip(sub, sup)))
    return sub == sup


def _matches(finding: dict, matcher: dict) -> bool:
    if "severity" in matcher and finding.get("severity") != matcher["severity"]:
        return False
    if "component" in matcher and finding.get("component") != matcher["component"]:
        return False
    if ("file_contains" in matcher
            and matcher["file_contains"] not in finding.get("file", "")):
        return False
    if ("evidence_contains" in matcher
            and matcher["evidence_contains"] not in finding.get("evidence", "")):
        return False
    if "detail" in matcher and not _subset(
            matcher["detail"], finding.get("detail") or {}):
        return False
    return True


def _positive_test(rid: str, case: dict):
    def test(self):
        rule = BY_ID[rid]
        findings = run_rule(rule, case_dir(case["dir"]))
        for matcher in case["expect"]:
            hits = [f for f in findings if _matches(f, matcher)]
            self.assertTrue(
                hits,
                f"{rid} positive '{case['name']}': no finding matched {matcher}; "
                f"findings={findings}")
    return test


def _negative_test(rid: str, case: dict):
    def test(self):
        rule = BY_ID[rid]
        findings = run_rule(rule, case_dir(case["negative"]["dir"]))
        leaked = [f for f in findings if f.get("id") == rid]
        self.assertEqual(
            leaked, [],
            f"{rid} negative: fixture must produce no finding; got {leaked}")
    return test


class TestRuleCoverage(unittest.TestCase):
    """Generated per-rule positive/negative tests (one method per fixture)."""


def _install_generated_tests() -> None:
    for rid, case in sorted(RULE_CASES.items()):
        safe = rid.replace("-", "_")
        for pos in case["positive"]:
            name = f"test_{safe}_positive_{pos['name']}"
            setattr(TestRuleCoverage, name, _positive_test(rid, pos))
        setattr(TestRuleCoverage, f"test_{safe}_negative",
                _negative_test(rid, case))


_install_generated_tests()


class TestRegistryAudit(unittest.TestCase):
    """The mapping must stay a complete, honest partition of the corpus."""

    def test_shipped_corpus_loads_clean(self):
        self.assertEqual(LOAD_ERRORS, [], f"rule load errors: {LOAD_ERRORS}")
        self.assertEqual(len(SHIPPED), 38)

    def test_mapping_partitions_shipped_rules(self):
        covered = set(RULE_CASES)
        untested = set(UNTESTED)
        shipped = set(BY_ID)
        self.assertEqual(covered & untested, set(),
                         "a rule cannot be covered and untested at once")
        self.assertEqual(covered | untested, shipped,
                         "every shipped rule needs a fixture case or an "
                         "UNTESTED entry with a reason")

    def test_every_entry_has_a_reason(self):
        for rid, reason in UNTESTED.items():
            self.assertTrue(reason and reason.strip(),
                            f"{rid}: untested entry needs a non-empty reason")

    def test_case_paths_match_rule_kinds(self):
        for rid, case in RULE_CASES.items():
            self.assertEqual(case["path"], BY_ID[rid].kind,
                             f"{rid}: mapping path must match the rule kind")

    def test_fixture_dirs_exist_and_are_nonempty(self):
        for rid, case in RULE_CASES.items():
            dirs = [p["dir"] for p in case["positive"]]
            dirs.append(case["negative"]["dir"])
            for rel in dirs:
                d = case_dir(rel)
                self.assertTrue(os.path.isdir(d), f"{rid}: missing {rel}")
                self.assertTrue(os.listdir(d), f"{rid}: empty {rel}")

    def test_positive_cases_have_matchers(self):
        for rid, case in RULE_CASES.items():
            for pos in case["positive"]:
                self.assertTrue(pos["expect"],
                                f"{rid}: positive '{pos['name']}' needs at "
                                f"least one finding matcher")


class TestCrossComponent(unittest.TestCase):
    """Rule loading -> scan -> stage status -> finding/evidence interactions."""

    def test_taint_fixture_stats_feed_stage_status(self):
        rule = BY_ID["AS-0033"]
        stats: dict = {}
        findings = TS.scan(case_dir("AS-0033/positive"), [rule], stats=stats)
        self.assertTrue(findings, "positive fixture must yield a finding")
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"smali-taint"}, taint_stats=stats)
        taint = [s for s in stages if s["stage"] == "smali-taint"][0]
        self.assertTrue(taint["ran"])
        self.assertTrue(taint["complete"], taint)
        status = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[],
            rule_errors=[], stages=stages)
        self.assertEqual(status["status"], "complete")

    def test_unrelated_gap_does_not_taint_finding_reason(self):
        """Observation 2 (Batch E review): a coverage gap in a method that is
        not part of a finding's propagation path must not be misrepresented as
        a gap in that finding; the global stage still goes partial."""
        stats: dict = {}
        findings = TS.scan(fixture("cross", "taint_unrelated_gap"),
                           [BY_ID["AS-0033"]], stats=stats)
        self.assertTrue(findings, "clean-method flow must still be found")
        for f in findings:
            analysis = f["detail"]["analysis"]
            self.assertEqual(analysis["status"], "partial")
            self.assertNotIn("coverage gaps", analysis["reason"],
                             "unrelated-method gap leaked into finding reason")
            self.assertEqual(analysis["reason"],
                             "intra-method CFG fixed-point scan; see limitations")
        self.assertGreaterEqual(stats["unsupported_instructions"], 1)
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"smali-taint"}, taint_stats=stats)
        taint = [s for s in stages if s["stage"] == "smali-taint"][0]
        self.assertFalse(taint["complete"])
        self.assertIn("parser coverage gaps", taint["reason"])
        status = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[],
            rule_errors=[], stages=stages)
        self.assertEqual(status["status"], "partial")
        self.assertTrue(any("smali-taint incomplete" in x
                            for x in status["limitations"]), status)

    def test_gap_in_finding_method_is_reported(self):
        """Complement of the test above: when the gap IS in the finding's own
        method, the per-method gap text must be attached."""
        findings = TS.scan(fixture("cross", "taint_gap_in_method"),
                           [BY_ID["AS-0033"]])
        self.assertTrue(findings)
        for f in findings:
            reason = f["detail"]["analysis"]["reason"]
            self.assertIn("method coverage gaps: 1 unsupported instruction(s)",
                          reason)

    def test_regex_fixture_stats_feed_stage_status(self):
        stats: dict = {}
        findings = AN.check_regex([BY_ID["AS-0013"]],
                                  case_dir("AS-0013/positive"), stats=stats)
        self.assertTrue(findings)
        self.assertEqual(stats["rules_evaluated"], 1)
        self.assertFalse(stats["truncated_any"])
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"regex"}, regex_stats=stats)
        regex = [s for s in stages if s["stage"] == "regex"][0]
        self.assertTrue(regex["ran"])
        self.assertTrue(regex["complete"], regex)
        status = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[],
            rule_errors=[], stages=stages)
        self.assertEqual(status["status"], "complete")

    def test_reach_fixture_coverage_feed_stage_status(self):
        dir_ = case_dir("AS-0038/positive")
        man = MF.parse(os.path.join(dir_, "AndroidManifest.xml"))
        coverage: dict = {}
        findings = CG.check_reachability(
            [BY_ID["AS-0038"]], dir_, man, coverage=coverage)
        self.assertTrue(findings)
        stages = AN.compute_stages(
            decoded_ok=True, has_manifest=True, manifest_only=False,
            do_regex=True, packed=[], has_so_files=False,
            kinds_present={"reachability"}, reach_coverage=coverage)
        reach = [s for s in stages if s["stage"] == "reachability"][0]
        self.assertTrue(reach["ran"])
        self.assertTrue(reach["complete"], reach)
        status = AN.build_analysis_status(
            decoded_ok=True, manifest_only=False, packed=[],
            rule_errors=[], stages=stages)
        self.assertEqual(status["status"], "complete")

    def test_finding_schema_and_evidence_across_paths(self):
        samples = (
            run_rule(BY_ID["AS-0001"], case_dir("AS-0001/positive"))
            + run_rule(BY_ID["AS-0013"], case_dir("AS-0013/positive"))
            + run_rule(BY_ID["AS-0033"], case_dir("AS-0033/positive"))
            + run_rule(BY_ID["AS-0038"], case_dir("AS-0038/positive"))
            + run_rule(BY_ID["AS-0027"], case_dir("AS-0027/positive"))
        )
        self.assertTrue(samples)
        for f in samples:
            for key in ("id", "tool", "rule", "title", "severity", "kind",
                        "component", "file", "evidence", "recommendation",
                        "maswe", "static_only", "verification"):
                self.assertIn(key, f, f"missing {key}: {f}")
            self.assertTrue(f["evidence"].strip(), f"empty evidence: {f}")
            self.assertTrue(f["recommendation"].strip(), f"no recommendation: {f}")
            self.assertTrue(f["static_only"])
            self.assertEqual(f["verification"]["status"], "unverified")
            self.assertEqual(f["id"], f["rule"])
        ordered = R.sort_findings(samples)
        self.assertEqual(
            [f["id"] for f in ordered],
            [f["id"] for f in R.sort_findings(list(reversed(samples)))],
            "sort_findings must be deterministic")
        ranks = [R.SEV_ORDER.get(f["severity"], 0) for f in ordered]
        self.assertEqual(ranks, sorted(ranks, reverse=True),
                         f"severities not ordered: {ranks}")

    def test_native_reuse_of_regex_rule_metadata(self):
        """check_native rescores carved strings against the SAME loaded
        AS-0021/AS-0016 rules -- a rule-loading -> evidence interaction."""
        import io
        lib = (b"\x00junk\x00https://tracker.example/collect\x00"
               b"AKIAIOSFODNN7EXAMPLE\x00")
        with tempfile.TemporaryDirectory() as td:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("lib/arm64-v8a/libx.so", lib)
            apk = os.path.join(td, "fixture.apk")
            with open(apk, "wb") as fh:
                fh.write(buf.getvalue())
            stats: dict = {}
            findings = AN.check_native(
                {"AS-0021": BY_ID["AS-0021"], "AS-0016": BY_ID["AS-0016"]},
                apk, stats=stats)
        ids = {f["id"] for f in findings}
        self.assertEqual(ids, {"AS-0021", "AS-0016"}, findings)
        for f in findings:
            self.assertEqual(f["detail"]["classification"], "candidate-string")
            self.assertIn("source_artifact_sha256", f["detail"])


if __name__ == "__main__":
    unittest.main()
