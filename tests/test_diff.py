"""D3 tests: coverage-aware diff semantics on top of legacy diff keys.

A finding that disappears from the new report is only confirmed
remediation when the relevant stage ran and completed in both runs, the
rule stayed loaded, and the artifact actually changed. Coverage,
rule-inventory, artifact and analysis-status changes are reported
separately so a partial or regressed run can never masquerade as a fix.
Legacy keys (findings_new/findings_resolved/...) are preserved.
"""
from __future__ import annotations

import unittest

from triagekit import diff
from triagekit import evidence as EV


def stage(name, *, ran=True, complete=True, reason="", status=None):
    return {"stage": name, "ran": ran, "complete": complete, "reason": reason}


def finding(rule="AS-0009", component="com.x/.P", title="t", severity="high",
            evidence="e", fid=None, file="", kind="manifest", detail=None):
    f = {"rule": rule, "component": component, "title": title,
         "severity": severity, "evidence": evidence, "file": file, "kind": kind}
    if fid:
        f["finding_id"] = fid
    if detail:
        f["detail"] = detail
    return f


def report(findings, *, status="complete", stages=None, sha="a" * 64,
           inventory=None):
    return {
        "package": "com.x", "version_name": "1.0", "apk_sha256": sha,
        "analysis": {"status": status, "stages": stages or [], "limitations": []},
        "rule_inventory": inventory or {"rules_loaded": 38, "errors": [],
                                        "rules_rejected": []},
        "findings": findings, "blind_spots": [],
    }


CLEAN_STAGES = [stage("manifest"), stage("regex"), stage("smali-taint"),
                stage("reachability")]


class TestLegacyPreserved(unittest.TestCase):
    def test_legacy_keys_still_present(self):
        old = report([finding(fid="id-a")])
        new = report([finding(rule="AS-0005", fid="id-b")], sha="b" * 64)
        d = diff.diff(old, new)
        for key in ("old", "new", "components_added", "components_removed",
                    "exported_added", "exported_removed", "export_state_changed",
                    "permissions_added", "permissions_removed", "schemes_added",
                    "schemes_removed", "findings_new", "findings_resolved",
                    "signer_changed", "risk_signals"):
            self.assertIn(key, d)
        self.assertEqual(d["findings_resolved"],
                         [{"rule": "AS-0009", "component": "com.x/.P", "title": "t"}])
        self.assertEqual(d["findings_new"],
                         [{"rule": "AS-0005", "component": "com.x/.P", "title": "t"}])


class TestFindingChanges(unittest.TestCase):
    def test_added_and_removed_by_id(self):
        old = report([finding(fid="id-a")])
        new = report([finding(rule="AS-0005", fid="id-b")], sha="b" * 64)
        d = diff.diff(old, new)
        fc = d["finding_changes"]
        self.assertEqual([x["id"] for x in fc["added"]], ["id-b"])
        self.assertEqual([x["id"] for x in fc["removed"]], ["id-a"])
        self.assertEqual(fc["matched_by"], "finding_id")

    def test_changed_fields(self):
        a = finding(fid="id-x", severity="high", evidence="one", detail={"line": 3})
        b = finding(fid="id-x", severity="low", evidence="two", detail={"line": 3})
        d = diff.diff(report([a]), report([b], sha="b" * 64))
        changed = d["finding_changes"]["changed"]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["id"], "id-x")
        self.assertEqual(sorted(changed[0]["fields"]), ["evidence", "severity"])

    def test_legacy_tuple_fallback_matching(self):
        old = report([finding(fid=None)])          # pre-EV-01 report
        new = report([finding(fid="id-new")], sha="b" * 64)
        d = diff.diff(old, new)
        fc = d["finding_changes"]
        self.assertEqual(fc["added"], [])
        self.assertEqual(fc["removed"], [])
        self.assertEqual(fc["matched_by"], "legacy-tuple")
        self.assertEqual(fc["unchanged"], 1)


class TestRemediationConfirmGate(unittest.TestCase):
    def _diff(self, old, new):
        return diff.diff(old, new)

    def test_confirmed_when_both_complete_and_artifact_changed(self):
        old = report([finding(fid="id-a")], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], stages=CLEAN_STAGES, sha="b" * 64)
        rem = self._diff(old, new)["finding_changes"]["removed"][0]
        self.assertTrue(rem["remediation_confirmed"])
        self.assertIn("complete", rem["reason"])

    def test_not_confirmed_when_new_stage_not_run(self):
        bad = [stage("manifest", ran=False, complete=False, reason="decode failed"),
               stage("regex"), stage("smali-taint"), stage("reachability")]
        old = report([finding(fid="id-a")], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], status="partial", stages=bad, sha="b" * 64)
        rem = self._diff(old, new)["finding_changes"]["removed"][0]
        self.assertFalse(rem["remediation_confirmed"])
        self.assertIn("manifest", rem["reason"])

    def test_not_confirmed_when_new_stage_truncated(self):
        bad = [stage("manifest", complete=False, reason="cap reached"),
               stage("regex"), stage("smali-taint"), stage("reachability")]
        old = report([finding(fid="id-a")], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], status="partial", stages=bad, sha="b" * 64)
        rem = self._diff(old, new)["finding_changes"]["removed"][0]
        self.assertFalse(rem["remediation_confirmed"])
        self.assertIn("cap reached", rem["reason"])

    def test_not_confirmed_when_old_run_partial(self):
        bad = [stage("manifest", complete=False, reason="was incomplete"),
               stage("regex"), stage("smali-taint"), stage("reachability")]
        old = report([finding(fid="id-a")], status="partial", stages=bad, sha="a" * 64)
        new = report([], stages=CLEAN_STAGES, sha="b" * 64)
        rem = self._diff(old, new)["finding_changes"]["removed"][0]
        self.assertFalse(rem["remediation_confirmed"])
        self.assertIn("old run", rem["reason"])

    def test_not_confirmed_when_rule_rejected_in_new_run(self):
        inv = {"rules_loaded": 37, "errors": ["AS-0009-regressed.json: rule AS-0009 unsupported kind"],
               "rules_rejected": ["AS-0009"]}
        old = report([finding(fid="id-a")], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], stages=CLEAN_STAGES, sha="b" * 64, inventory=inv)
        rem = self._diff(old, new)["finding_changes"]["removed"][0]
        self.assertFalse(rem["remediation_confirmed"])
        self.assertIn("AS-0009", rem["reason"])

    def test_not_confirmed_when_artifact_unchanged(self):
        old = report([finding(fid="id-a")], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], stages=CLEAN_STAGES, sha="a" * 64)
        rem = self._diff(old, new)["finding_changes"]["removed"][0]
        self.assertFalse(rem["remediation_confirmed"])
        self.assertIn("nondetermin", rem["reason"])

    def test_not_confirmed_without_stage_records(self):
        old = report([finding(fid="id-a")], sha="a" * 64)
        new = report([], sha="b" * 64)
        rem = self._diff(old, new)["finding_changes"]["removed"][0]
        self.assertFalse(rem["remediation_confirmed"])
        self.assertIn("stage", rem["reason"])

    def test_native_findings_attributed_to_native_stage(self):
        f = finding(fid="id-n", kind="regex", file="lib/x.so",
                    detail={"file_offset": 10, "source_artifact_sha256": "c" * 64})
        stages = CLEAN_STAGES + [stage("native")]
        old = report([f], stages=stages, sha="a" * 64)
        new = report([], stages=stages, sha="b" * 64)
        rem = self._diff(old, new)["finding_changes"]["removed"][0]
        self.assertTrue(rem["remediation_confirmed"])
        self.assertIn("native", rem["reason"])

    def test_cross_app_removal_never_confirmed(self):
        old = report([finding(fid="id-a")], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], stages=CLEAN_STAGES, sha="b" * 64)
        old["package"] = "com.bank.app"
        new["package"] = "com.unrelated.app"
        d = self._diff(old, new)
        rem = d["finding_changes"]["removed"][0]
        self.assertFalse(rem["remediation_confirmed"])
        self.assertIn("package", rem["reason"].lower())
        self.assertTrue(any("PACKAGE" in s for s in d["risk_signals"]),
                        d["risk_signals"])


class TestWatchedFlags(unittest.TestCase):
    def test_every_spec_flag_change_is_a_risk_signal(self):
        from triagekit.manifest import FLAG_SPEC
        old = report([])
        new = report([])
        old["flags"] = {k: "off" for k in FLAG_SPEC}
        new["flags"] = {k: "on" for k in FLAG_SPEC}
        signals = diff.diff(old, new)["risk_signals"]
        missing = [k for k in FLAG_SPEC if not any(k in s for s in signals)]
        self.assertEqual(missing, [], f"unwatched flag keys: {missing}")


class TestIdentityCollisionRemediation(unittest.TestCase):
    """F3: a removal claim must concern an id genuinely absent from the new run."""

    @staticmethod
    def _reach(sink, evidence):
        return {"rule": "AS-0038", "component": "com.x/.P", "title": "t",
                "severity": "high", "evidence": evidence,
                "file": "smali/com/x/A.smali", "kind": "reachability",
                "detail": {"sink": sink, "src_line": 10}}

    def test_collision_does_not_mask_survivor(self):
        old_f = [self._reach("Lx/WebView;->loadUrl(Ljava/lang/String;)V",
                             "A:10 exported activity reaches loadUrl"),
                 self._reach("Lx/Runtime;->exec(Ljava/lang/String;)V",
                             "A:10 exported activity reaches exec")]
        new_f = [self._reach("Lx/Runtime;->exec(Ljava/lang/String;)V",
                             "A:10 exported activity reaches exec")]
        EV.assign_finding_ids(old_f)
        EV.assign_finding_ids(new_f)
        old = report(old_f, stages=CLEAN_STAGES, sha="a" * 64)
        new = report(new_f, stages=CLEAN_STAGES, sha="b" * 64)
        fc = diff.diff(old, new)["finding_changes"]
        removed_ids = [r["id"] for r in fc["removed"]]
        self.assertEqual(removed_ids, [old_f[0]["finding_id"]])
        self.assertTrue(fc["removed"][0]["remediation_confirmed"])
        self.assertFalse(set(removed_ids) & {f["finding_id"] for f in new_f})
        self.assertEqual(fc["changed"], [])
        self.assertEqual(fc["unchanged"], 1)
        self.assertEqual(fc["added"], [])

    def test_suffixed_removal_not_confirmed(self):
        d = "0123456789abcdef"
        old = report([finding(fid=d, kind="reachability",
                              detail={"sink": "Lx/W;->loadUrl()V"}),
                      finding(fid=d + "-2", kind="reachability",
                              detail={"sink": "Lx/W;->loadUrl()V"})],
                     stages=CLEAN_STAGES, sha="a" * 64)
        new = report([finding(fid=d, kind="reachability",
                              detail={"sink": "Lx/W;->loadUrl()V"})],
                     stages=CLEAN_STAGES, sha="b" * 64)
        removed = diff.diff(old, new)["finding_changes"]["removed"]
        self.assertEqual([r["id"] for r in removed], [d + "-2"])
        self.assertFalse(removed[0]["remediation_confirmed"])
        self.assertIn("ambiguous", removed[0]["reason"])


class TestCoverageAndContextBlocks(unittest.TestCase):
    def test_coverage_change_block(self):
        old = report([], status="partial", stages=[stage("manifest", complete=False,
                                                         reason="x")], sha="a" * 64)
        new = report([], stages=CLEAN_STAGES, sha="b" * 64)
        cc = diff.diff(old, new)["coverage_change"]
        self.assertEqual(cc["old_status"], "partial")
        self.assertEqual(cc["new_status"], "complete")
        self.assertFalse(cc["regressed"])
        stages = {s["stage"]: s for s in cc["stage_changes"]}
        self.assertEqual(stages["manifest"]["from"], False)
        self.assertEqual(stages["manifest"]["to"], True)

    def test_coverage_regression_flagged(self):
        old = report([], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], status="partial",
                     stages=[stage("manifest", ran=False, complete=False, reason="x")],
                     sha="b" * 64)
        cc = diff.diff(old, new)["coverage_change"]
        self.assertTrue(cc["regressed"])
        self.assertIsNotNone(cc["notice"])

    def test_notice_marks_unconfirmed_removals(self):
        bad = [stage("manifest", ran=False, complete=False, reason="decode failed")]
        old = report([finding(fid="id-a")], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], status="partial", stages=bad, sha="b" * 64)
        cc = diff.diff(old, new)["coverage_change"]
        self.assertIn("not confirmed", cc["notice"].lower())

    def test_rule_inventory_change_block(self):
        inv = {"rules_loaded": 37, "errors": ["boom"], "rules_rejected": []}
        old = report([], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], stages=CLEAN_STAGES, sha="b" * 64, inventory=inv)
        ric = diff.diff(old, new)["rule_inventory_change"]
        self.assertTrue(ric["changed"])
        self.assertEqual(ric["old_rules_loaded"], 38)
        self.assertEqual(ric["new_rules_loaded"], 37)
        self.assertEqual(ric["new_errors"], ["boom"])

    def test_artifact_change_block(self):
        old = report([], stages=CLEAN_STAGES, sha="a" * 64)
        same = report([], stages=CLEAN_STAGES, sha="a" * 64)
        other = report([], stages=CLEAN_STAGES, sha="b" * 64)
        self.assertFalse(diff.diff(old, same)["artifact_change"]["changed"])
        ac = diff.diff(old, other)["artifact_change"]
        self.assertTrue(ac["changed"])
        self.assertEqual(ac["old_sha256"], "a" * 64)
        self.assertEqual(ac["new_sha256"], "b" * 64)

    def test_analysis_status_change_block(self):
        old = report([], status="partial", stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], stages=CLEAN_STAGES, sha="b" * 64)
        asc = diff.diff(old, new)["analysis_status_change"]
        self.assertEqual(asc["from"], "partial")
        self.assertEqual(asc["to"], "complete")
        self.assertFalse(asc["regressed"])
        back = diff.diff(new, old)["analysis_status_change"]
        self.assertTrue(back["regressed"])


class TestRender(unittest.TestCase):
    def test_render_shows_remediation_status(self):
        bad = [stage("manifest", ran=False, complete=False, reason="decode failed")]
        old = report([finding(fid="id-a")], stages=CLEAN_STAGES, sha="a" * 64)
        new = report([], status="partial", stages=bad, sha="b" * 64)
        text = diff.render(diff.diff(old, new))
        self.assertIn("Findings removed", text)
        self.assertIn("not confirmed", text.lower())

    def test_render_legacy_dict_unchanged(self):
        legacy = {"old": {"package": "com.x", "version_name": "1"},
                  "new": {"package": "com.x", "version_name": "2"},
                  "risk_signals": [], "components_added": [], "components_removed": [],
                  "exported_added": [], "exported_removed": [], "export_state_changed": [],
                  "permissions_added": [], "permissions_removed": [], "schemes_added": [],
                  "schemes_removed": [], "findings_new": [], "findings_resolved": []}
        text = diff.render(legacy)
        self.assertIn("Findings new (0)", text)
        self.assertNotIn("Findings removed", text)


if __name__ == "__main__":
    unittest.main()
