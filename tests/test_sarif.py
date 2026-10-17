"""SARIF 2.1.0 renderer tests: honest locations and completeness signals.

Every assertion is about evidence that exists (or does not exist) in the
report; no location or line is ever invented, and an incomplete or
unrecorded analysis run must not look "clean" to CI consumers.
"""
from __future__ import annotations

import unittest

from triagekit import sarif as SARIF


def _finding(**kw):
    f = {"rule": "X-0001", "title": "t", "evidence": "e",
         "severity": "high", "file": "a/b.smali", "detail": {}}
    f.update(kw)
    return f


class TestLocations(unittest.TestCase):
    def _loc(self, finding):
        out = SARIF.convert({"findings": [finding]}, [])
        return out["runs"][0]["results"][0]["locations"]

    def test_sink_line_is_used_when_line_absent(self):
        loc = self._loc(_finding(detail={"sink_line": 20}))
        self.assertEqual(loc[0]["physicalLocation"]["region"],
                         {"startLine": 20})

    def test_explicit_line_wins(self):
        loc = self._loc(_finding(detail={"line": 7, "sink_line": 20}))
        self.assertEqual(loc[0]["physicalLocation"]["region"],
                         {"startLine": 7})

    def test_unknown_line_omits_region(self):
        loc = self._loc(_finding(detail={}))
        self.assertNotIn("region", loc[0]["physicalLocation"])
        loc = self._loc(_finding(detail={"line": None}))
        self.assertNotIn("region", loc[0]["physicalLocation"])

    def test_zero_line_omits_region(self):
        loc = self._loc(_finding(detail={"line": 0}))
        self.assertNotIn("region", loc[0]["physicalLocation"])

    def test_no_file_yields_no_locations(self):
        loc = self._loc(_finding(file=""))
        self.assertEqual(loc, [])


class TestCompleteness(unittest.TestCase):
    PARTIAL = {
        "status": "partial",
        "stages": [{"stage": "smali-taint", "ran": True, "complete": False,
                    "reason": "2 file(s) truncated at the read cap"}],
        "limitations": ["smali taint is an intra-method scan"],
    }

    def _run(self, report):
        return SARIF.convert(report, [])["runs"][0]

    def test_partial_run_is_not_success(self):
        run = self._run({"findings": [], "analysis": self.PARTIAL})
        inv = run["invocations"][0]
        self.assertFalse(inv["executionSuccessful"])
        texts = " ".join(n["message"]["text"]
                         for n in inv["toolExecutionNotifications"])
        self.assertIn("smali-taint", texts)
        self.assertIn("truncated", texts)

    def test_not_analysed_is_not_success(self):
        run = self._run({"findings": [], "analysis": {
            "status": "not_analysed", "stages": [], "limitations": []}})
        inv = run["invocations"][0]
        self.assertFalse(inv["executionSuccessful"])
        self.assertTrue(inv["toolExecutionNotifications"])

    def test_complete_run_is_success_without_notifications(self):
        run = self._run({"findings": [], "analysis": {
            "status": "complete", "stages": [], "limitations": []}})
        inv = run["invocations"][0]
        self.assertTrue(inv["executionSuccessful"])
        self.assertNotIn("toolExecutionNotifications", inv)

    def test_missing_analysis_status_is_not_silent(self):
        run = self._run({"findings": []})
        inv = run["invocations"][0]
        self.assertFalse(inv["executionSuccessful"])
        self.assertTrue(inv["toolExecutionNotifications"])


if __name__ == "__main__":
    unittest.main()
