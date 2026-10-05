"""Rule registry.

A rule is a small JSON (or YAML, if PyYAML happens to be present) document.
Third parties add findings by adding a file to rules/ — no Python required.
This is the same plugin shape as a hook module manifest, deliberately.
"""
from __future__ import annotations

import json
import os
import re

try:  # optional
    import yaml  # type: ignore
    _YAML = True
except Exception:  # noqa: BLE001
    _YAML = False

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_ORDER = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 .. critical=4

REQUIRED = ("id", "title", "kind", "severity")


class Rule:
    __slots__ = ("raw", "id", "title", "kind", "severity", "maswe", "recommendation",
                 "check", "params", "recommendation_text", "repro", "path", "tags")

    def __init__(self, raw: dict, path: str = ""):
        self.raw = raw
        self.path = path
        self.id = str(raw.get("id", ""))
        self.title = str(raw.get("title", ""))
        self.kind = str(raw.get("kind", ""))
        self.severity = str(raw.get("severity", "info")).lower()
        self.maswe = raw.get("maswe")
        self.check = raw.get("check")
        self.params = raw.get("params") or {}
        self.recommendation = raw.get("recommendation") or ""
        self.repro = raw.get("repro") or ""
        self.tags = raw.get("tags") or []

    def rank(self) -> int:
        return SEV_ORDER.get(self.severity, 0)

    def __repr__(self):
        return f"<Rule {self.id} {self.kind}/{self.check or ''}>"


def _load_file(path: str) -> list[Rule]:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith((".yaml", ".yml")):
        if not _YAML:
            raise RuntimeError(f"{path}: YAML rule needs PyYAML (pip install pyyaml)")
        docs = list(yaml.safe_load_all(text))
    else:
        docs = [json.loads(text)]
    rules = []
    for d in docs:
        if isinstance(d, list):
            rules += [Rule(x, path) for x in d]
        elif isinstance(d, dict) and d:
            rules.append(Rule(d, path))
    return rules


def load_dir(rules_dir: str) -> tuple[list[Rule], list[str]]:
    """Return (rules, errors). Broken rule files never abort the scan."""
    rules, errors = [], []
    if not os.path.isdir(rules_dir):
        return rules, [f"rules dir not found: {rules_dir}"]
    for fn in sorted(os.listdir(rules_dir)):
        if not fn.endswith((".json", ".yaml", ".yml")):
            continue
        p = os.path.join(rules_dir, fn)
        try:
            got = _load_file(p)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{fn}: {e}")
            continue
        for r in got:
            missing = [k for k in REQUIRED if not getattr(r, k, None)]
            if missing:
                errors.append(f"{fn}: rule {r.id or '?'} missing {','.join(missing)}")
                continue
            if r.severity not in SEVERITIES:
                errors.append(f"{fn}: rule {r.id} bad severity {r.severity!r}")
                continue
            rules.append(r)
    return rules, errors


# ------------------------------------------------------------------ findings
def finding(rule: Rule, *, component: str = "", evidence: str = "",
            file: str = "", extra: dict | None = None) -> dict:
    """Build a finding in the shared schema (see DESIGN doc)."""
    f = {
        "id": rule.id,
        "tool": "apk-surface",
        "rule": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "kind": rule.kind,
        "component": component,
        "file": file,
        "evidence": evidence,
        "recommendation": rule.recommendation,
        "maswe": rule.maswe,
        "static_only": True,
        "verification": {"status": "unverified", "script": None},
    }
    if extra:
        f["detail"] = extra
    return f


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (-SEV_ORDER.get(f.get("severity", "info"), 0),
                                           f.get("rule", ""), f.get("component", "")))


def fmt_repro(rule: Rule, ctx: dict) -> str:
    """Render the rule's repro template, leaving unknown placeholders visible."""
    if not rule.repro:
        return ""
    out = rule.repro
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", str(v))
    # anything still in braces is a template var the caller did not supply
    return out
