"""Severity-order contract (isolated fix): critical > high > medium > low > info.

Engine ordering (rules.sort_findings), JSON serialization, and rendered report
sections must all agree, equal-severity findings must sort deterministically,
and sorting must not touch finding identity or content.
"""
from __future__ import annotations

import json
import unittest

from triagekit import report as RP
from triagekit import rules as R

CONTRACT = ["critical", "high", "medium", "low", "info"]


def _finding(rule: str, sev: str, component: str = "") -> dict:
    return {"id": rule, "tool": "apk-surface", "rule": rule,
            "title": f"title {rule}", "severity": sev, "kind": "manifest",
            "component": component, "file": "",
            "evidence": f"evidence for {rule}", "recommendation": "fix it",
            "maswe": None, "static_only": True,
            "verification": {"status": "unverified", "script": None}}


def _mixed() -> list[dict]:
    return [
        _finding("AS-9005", "info", "com.example.i"),
        _finding("AS-9002", "high", "com.example.h2"),
        _finding("AS-9001", "critical", "com.example.c"),
        _finding("AS-9004", "low", "com.example.l"),
        _finding("AS-9003", "medium", "com.example.m"),
        _finding("AS-9002b", "high", "com.example.h1"),
    ]


def _report_sections(text: str) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        if line.startswith("### "):
            name = line.split()[-2].casefold()
            if name in CONTRACT:
                sections.append((name, []))
        elif sections and line.startswith("**`"):
            sections[-1][1].append(line.split("`")[1])
    return sections


class TestFindingOrder(unittest.TestCase):
    def test_mixed_severity_order_is_critical_first(self):
        ordered = R.sort_findings(_mixed())
        self.assertEqual([f["severity"] for f in ordered],
                         ["critical", "high", "high", "medium", "low", "info"])

    def test_equal_severity_tiebreak_is_deterministic(self):
        a = _finding("AS-0002", "high", "com.example.b")
        b = _finding("AS-0001", "high", "com.example.a")
        c = _finding("AS-0001", "high", "com.example.0")
        forward = R.sort_findings([a, b, c])
        backward = R.sort_findings([c, b, a])
        self.assertEqual([(f["id"], f["component"]) for f in forward],
                         [("AS-0001", "com.example.0"),
                          ("AS-0001", "com.example.a"),
                          ("AS-0002", "com.example.b")])
        self.assertEqual([(f["id"], f["component"]) for f in forward],
                         [(f["id"], f["component"]) for f in backward])

    def test_json_and_report_agree_on_severity_priority(self):
        ordered = R.sort_findings(_mixed())
        payload = json.loads(json.dumps({"findings": ordered}))
        json_seq = [f["severity"] for f in payload["findings"]]
        json_groups = list(dict.fromkeys(json_seq))
        sections = _report_sections(RP.render({"findings": ordered}))
        report_groups = [s[0] for s in sections]
        self.assertEqual(json_groups, report_groups)
        self.assertEqual(report_groups, CONTRACT)
        for severity, ids in sections:
            expected = [f["id"] for f in ordered if f["severity"] == severity]
            self.assertEqual(ids, expected)

    def test_sort_preserves_finding_identity_and_content(self):
        findings = _mixed()
        before_ids = [f["id"] for f in findings]
        before_by_id = {f["id"]: dict(f) for f in findings}
        ordered = R.sort_findings(findings)
        self.assertIsNot(ordered, findings)
        self.assertEqual([f["id"] for f in findings], before_ids)
        self.assertEqual({id(f) for f in ordered}, {id(f) for f in findings})
        for f in ordered:
            self.assertEqual(f, before_by_id[f["id"]])


if __name__ == "__main__":
    unittest.main()
