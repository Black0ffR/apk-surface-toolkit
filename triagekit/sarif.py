"""SARIF 2.1.0 report renderer (CI/CD ingest: GitHub code scanning, etc.)."""
from __future__ import annotations

import hashlib
import json

_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}
TOOL = "apk-surface"


def _level(f: dict) -> str:
    return _LEVEL.get(str(f.get("severity", "")).lower(), "note")


def _rule_object(rule: dict) -> dict:
    return {
        "id": rule.get("rule", rule.get("id", "?")),
        "name": rule.get("title", ""),
        "help": {"text": rule.get("recommendation", "")},
    }


def _location(f: dict) -> list:
    if not f.get("file"):
        return []
    return [{"physicalLocation": {
        "artifactLocation": {"uri": f["file"]},
        "region": {"startLine": (f.get("detail") or {}).get("line", 1)},
    }}]


def _fingerprint(f: dict) -> str:
    h = hashlib.sha256()
    h.update("|".join(str(f.get(k, "")) for k in
                      ("rule", "component", "evidence")).encode())
    return h.hexdigest()[:32]


def convert(report: dict, rules: list) -> dict:
    seen, rule_objs = set(), []
    for r in rules:
        rid = r.get("rule", r.get("id"))
        if rid and rid not in seen:
            seen.add(rid)
            rule_objs.append(_rule_object(r))
    results = []
    for f in report.get("findings", []):
        results.append({
            "ruleId": f.get("rule", "?"),
            "level": _level(f),
            "message": {"text": f"{f.get('title', '')} — {f.get('evidence', '')}"[:1000]},
            "locations": _location(f),
            "fingerprints": {"primaryLocationLineHash": _fingerprint(f)},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL,
                                "version": report.get("version", "?"),
                                "rules": rule_objs}},
            "results": results,
        }],
    }


def write(report: dict, rules: list, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(convert(report, rules), fh, indent=2, ensure_ascii=False)
    return path
