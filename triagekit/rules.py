"""Rule registry.

A rule is a small JSON (or YAML, if PyYAML happens to be present) document.
Third parties add findings by adding a file to rules/ — no Python required.
This is the same plugin shape as a hook module manifest, deliberately.
"""
from __future__ import annotations

import json
import math
import os
import re

try:  # optional
    import yaml  # type: ignore
    _YAML = True
except Exception:  # noqa: BLE001
    _YAML = False

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}  # info=0 .. critical=4

REQUIRED = ("id", "title", "kind", "severity")

# Rule kinds the analyzer knows how to execute. Anything else is rejected
# with an explicit error (migration note in the message) rather than silently
# skipped: a rule that never runs must never look like a clean result.
SUPPORTED_KINDS = ("manifest", "regex", "smali-taint", "reachability")

# Dispatch values understood by the analyzer. `check` is optional (regex
# rules AS-0013..AS-0019 carry kind-only dispatch); when present it must be
# one of these. Unknown values are rejected, not ignored.
SUPPORTED_CHECKS = (
    "unprotected_exported", "undeclared_permission", "provider_exposed",
    "flag", "nsc", "custom_scheme", "deeplink_unverified",
    "dangerous_permission", "custom_permission_weak", "regex",
    "paths_traversal", "meta_data_secret", "strandhogg", "tapjacking",
    "sig_verdict", "nsc_hardening", "backup_rules", "risky_flags",
    "smali_taint", "weak_permission_exported", "deeplink_autoverify_custom",
    "nsc_missing", "reachability",
)


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


def _is_int_like(value: object) -> bool:
    # Booleans are never integers here: True would otherwise pass as 1.
    return isinstance(value, bool) is False and (
        isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit())
    )


def _is_finite_number(value: object) -> bool:
    """Finite int/float for numeric params. Rejects bools, NaN, and infinities."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


_TAINT_MATCH_MODES = ("owner-name", "name", "regex")
_TAINT_ENTRY_KEYS = frozenset({"owner", "name", "match", "argument_indexes"})
_MAX_TAINT_REGEX_LEN = 500
_RE_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)[+*]")


def _validate_taint_regex(name: str) -> str | None:
    if len(name) > _MAX_TAINT_REGEX_LEN:
        return f"regex name too long ({len(name)} > {_MAX_TAINT_REGEX_LEN})"
    if _RE_NESTED_QUANTIFIER.search(name):
        return "regex name contains a nested quantifier (ReDoS shape)"
    try:
        re.compile(name, re.I)
    except re.error as e:
        return f"bad regex name: {e}"
    return None


def _validate_taint_matchers(values: object, *, field: str, allow_indexes: bool,
                             prefix: str, sink_context: bool = False,
                             sanitizer_contexts: bool = False,
                             skip_missing: bool = False) -> tuple[list[str], list[str]]:
    """Validate one smali-taint sources/sinks/sanitizers list.

    Entries are legacy bare strings (load with a deprecation warning) or
    mappings {owner?, name, match?, argument_indexes?} plus `context` for
    sinks and `contexts` for sanitizers. Returns (errors, warnings); a
    malformed entry rejects only its own rule.
    """
    errs: list[str] = []
    warns: list[str] = []
    if skip_missing and values is None:
        return errs, warns
    if not isinstance(values, list) or not values:
        return [f"{prefix} {field} must be a non-empty list of matchers"], warns
    allowed = set(_TAINT_ENTRY_KEYS)
    if sink_context:
        allowed.add("context")
    if sanitizer_contexts:
        allowed.add("contexts")
    allowed_txt = ", ".join(
        k for k in ("owner", "name", "match", "argument_indexes",
                    "context", "contexts") if k in allowed)
    for index, entry in enumerate(values):
        where = f"{field}[{index}]"
        if isinstance(entry, str):
            if not entry.strip():
                errs.append(f"{prefix} {where} must not be empty")
            elif "\n" in entry or "\r" in entry:
                errs.append(f"{prefix} {where} must not contain newlines")
            else:
                warns.append(
                    f"{prefix} {where} bare string {entry!r} is legacy; prefer "
                    f'{{"name": ..., "match": "name"}} or an owner-scoped entry')
            continue
        if not isinstance(entry, dict):
            errs.append(f"{prefix} {where} must be a string or a mapping")
            continue
        for key in sorted(entry):
            if key not in allowed:
                errs.append(f"{prefix} {where} unknown key {key!r} "
                            f"(allowed: {allowed_txt})")
        has_owner = "owner" in entry
        if has_owner:
            owner = entry["owner"]
            if (not isinstance(owner, str) or not owner.strip()
                    or any(c.isspace() for c in owner)):
                errs.append(f"{prefix} {where} owner must be a non-empty "
                            "smali type descriptor without whitespace")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            errs.append(f'{prefix} {where} needs a non-empty string "name"')
        elif "\n" in name or "\r" in name:
            errs.append(f"{prefix} {where} name must not contain newlines")
        mode = entry.get("match", "owner-name" if has_owner else "name")
        if mode not in _TAINT_MATCH_MODES:
            errs.append(f"{prefix} {where} bad match mode {mode!r} "
                        f"(supported: {', '.join(_TAINT_MATCH_MODES)})")
        elif mode == "owner-name" and not has_owner:
            errs.append(f"{prefix} {where} match \"owner-name\" requires an owner")
        else:
            if mode == "name" and has_owner:
                errs.append(f"{prefix} {where} match \"name\" must not carry an "
                            "owner (use \"owner-name\" or \"regex\")")
            if mode == "regex" and isinstance(name, str) and name.strip():
                err = _validate_taint_regex(name)
                if err:
                    errs.append(f"{prefix} {where} {err}")
        if "argument_indexes" in entry:
            if not allow_indexes:
                errs.append(f"{prefix} {where} argument_indexes is only valid for sinks")
            else:
                idx = entry["argument_indexes"]
                ok = (isinstance(idx, list) and bool(idx)
                      and all(isinstance(i, int) and not isinstance(i, bool) and i >= 0
                              for i in idx))
                if not ok:
                    errs.append(f"{prefix} {where} argument_indexes must be a "
                                "non-empty list of integers >= 0")
        if "context" in entry:
            context = entry["context"]
            if (not isinstance(context, str) or not context.strip()
                    or "\n" in context or "\r" in context):
                errs.append(f"{prefix} {where} context must be a non-empty string")
        if "contexts" in entry:
            contexts = entry["contexts"]
            if not isinstance(contexts, list) or not contexts:
                errs.append(f"{prefix} {where} contexts must be a non-empty "
                            "list of strings")
            else:
                for context in contexts:
                    if (not isinstance(context, str) or not context.strip()
                            or "\n" in context or "\r" in context):
                        errs.append(f"{prefix} {where} contexts entries must be "
                                    "non-empty strings")
                        break
    return errs, warns


# Param keys the analyzer reads per rule kind. Unknown keys produce a warning
# (the rule still loads) rather than an error: forward compatibility for new
# options. Manifest rules accept the union of check-specific options below.
KNOWN_PARAMS = {
    "regex": {"pattern", "exts", "root", "skip_dirs", "entropy_min",
              "multiline", "include_vendor"},
    "smali-taint": {"sources", "sinks", "sanitizers", "interprocedural",
                    "cap", "root", "skip_dirs", "include_vendor"},
    "reachability": {"sinks", "cap", "reach_limit", "traversal_limit"},
    "manifest": {"flag", "value", "values", "flags", "want", "names", "modes",
                 "file_provider_classes", "file_provider_severity",
                 "nonexported_grant_severity", "webSchemes", "minTargetSdk"},
}


def _validate_str_list(values: object, *, field: str, allow_empty: bool = False) -> str | None:
    """Return an error string, or None when valid."""
    if not isinstance(values, list) or (not values and not allow_empty):
        return f"{field} must be a non-empty list of strings"
    for v in values:
        if not isinstance(v, str) or not v.strip():
            return f"{field} entries must be non-empty strings"
        if "\n" in v or "\r" in v:
            return f"{field} entries must not contain newlines"
    return None


def _validate_cap(params: dict) -> str | None:
    if "cap" not in params:
        return None
    cap = params["cap"]
    if not _is_int_like(cap) or int(cap) <= 0:
        return f"bad cap {cap!r}: must be an integer > 0"
    return None


def _validate_rule(rule: Rule, filename: str) -> tuple[list[str], list[str]]:
    """Deterministic per-rule validation.

    Returns (errors, warnings). Errors reject the rule; warnings flag unknown
    params without rejecting (forward compatibility). Never silently discards.
    """
    errs: list[str] = []
    warns: list[str] = []
    if not isinstance(rule.raw, dict):
        return [f"{filename}: rule is not a mapping"], warns
    if rule.kind not in SUPPORTED_KINDS:
        errs.append(f"{filename}: rule {rule.id or '?'} unsupported kind {rule.kind!r} "
                    f"(supported: {', '.join(SUPPORTED_KINDS)}; migrate the rule kind)")
        return errs, warns
    if rule.check is not None and rule.check not in SUPPORTED_CHECKS:
        errs.append(f"{filename}: rule {rule.id} unsupported check {rule.check!r} "
                    f"(migrate to one of: {', '.join(SUPPORTED_CHECKS)})")
    params = rule.params
    if not isinstance(params, dict):
        return errs + [f"{filename}: rule {rule.id} params must be a mapping"], warns
    for key in sorted(params):
        if key not in KNOWN_PARAMS.get(rule.kind, set()):
            warns.append(f"{filename}: rule {rule.id} unknown param {key!r} (ignored)")
    cap_err = _validate_cap(params)
    if cap_err:
        errs.append(f"{filename}: rule {rule.id} {cap_err}")
    if "minTargetSdk" in params and (
            not _is_int_like(params["minTargetSdk"]) or int(params["minTargetSdk"]) <= 0):
        errs.append(f"{filename}: rule {rule.id} bad minTargetSdk "
                    f"{params['minTargetSdk']!r}: must be an integer > 0")
    if rule.kind == "regex":
        pat = params.get("pattern")
        if not isinstance(pat, str) or not pat:
            errs.append(f"{filename}: rule {rule.id} missing regex pattern")
        else:
            try:
                re.compile(pat, re.I)
            except re.error as e:
                errs.append(f"{filename}: rule {rule.id} bad regex pattern: {e}")
        for key in ("exts", "skip_dirs"):
            if key in params and (
                    not isinstance(params[key], list)
                    or any(not isinstance(x, str) for x in params[key])):
                errs.append(f"{filename}: rule {rule.id} {key} must be a list of strings")
        if "root" in params and not isinstance(params["root"], str):
            errs.append(f"{filename}: rule {rule.id} root must be a string")
        if "entropy_min" in params and (
                not _is_finite_number(params["entropy_min"])
                or params["entropy_min"] < 0):
            errs.append(f"{filename}: rule {rule.id} entropy_min must be a finite number >= 0")
        if "multiline" in params and not isinstance(params["multiline"], bool):
            errs.append(f"{filename}: rule {rule.id} multiline must be boolean")
    elif rule.kind == "smali-taint":
        prefix = f"{filename}: rule {rule.id}"
        for field, allow_indexes, sink_ctx, san_ctx, skip_missing in (
                ("sources", False, False, False, False),
                ("sinks", True, True, False, False),
                ("sanitizers", True, False, True, True)):
            merrs, mwarns = _validate_taint_matchers(
                params.get(field), field=field, allow_indexes=allow_indexes,
                prefix=prefix, sink_context=sink_ctx,
                sanitizer_contexts=san_ctx, skip_missing=skip_missing)
            errs.extend(merrs)
            warns.extend(mwarns)
        if "interprocedural" in params and not isinstance(
                params["interprocedural"], bool):
            errs.append(f"{filename}: rule {rule.id} interprocedural must be boolean")
        for key in ("root",):
            if key in params and not isinstance(params[key], str):
                errs.append(f"{filename}: rule {rule.id} {key} must be a string")
        if "skip_dirs" in params and (
                not isinstance(params["skip_dirs"], list)
                or any(not isinstance(x, str) for x in params["skip_dirs"])):
            errs.append(f"{filename}: rule {rule.id} skip_dirs must be a list of strings")
        if "include_vendor" in params and not isinstance(params["include_vendor"], bool):
            errs.append(f"{filename}: rule {rule.id} include_vendor must be boolean")
    elif rule.kind == "reachability":
        err = _validate_str_list(params.get("sinks"), field="sinks")
        if err:
            errs.append(f"{filename}: rule {rule.id} {err}")
        for key in ("reach_limit", "traversal_limit"):
            if key in params and (not _is_int_like(params[key]) or int(params[key]) <= 0):
                errs.append(f"{filename}: rule {rule.id} bad {key} {params[key]!r}: "
                            "must be an integer > 0")
    return errs, warns


def load_dir(rules_dir: str, inventory: dict | None = None) -> tuple[list[Rule], list[str]]:
    """Return (rules, errors). Broken rule files never abort the scan.

    When `inventory` is given it is filled with `files_seen`,
    `rules_loaded`, `rules_rejected` (per-rule rejections only),
    `files_failed` (rule files that could not be parsed at all),
    `duplicate_ids`, `errors`, and `warnings` (unknown params; the rule
    still loads). Non-rule dependency failures (missing dir, broken JSON,
    YAML without PyYAML) are file errors, never rule rejections.
    Duplicate IDs keep the first file's rule; later copies are rejected with
    an explicit error (never silently dropped).
    """
    rules, errors = [], []
    warnings: list[str] = []
    seen: dict[str, str] = {}
    duplicate_ids: list[str] = []
    files_seen = 0
    rejected = 0
    files_failed = 0
    if not os.path.isdir(rules_dir):
        errs = [f"rules dir not found: {rules_dir}"]
        if inventory is not None:
            inventory.update({"files_seen": 0, "rules_loaded": 0,
                              "rules_rejected": 0, "files_failed": 0,
                              "duplicate_ids": [], "errors": errs,
                              "warnings": []})
        return rules, errs
    for fn in sorted(os.listdir(rules_dir)):
        if not fn.endswith((".json", ".yaml", ".yml")):
            continue
        files_seen += 1
        p = os.path.join(rules_dir, fn)
        try:
            got = _load_file(p)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{fn}: {e}")
            files_failed += 1
            continue
        for r in got:
            if not isinstance(getattr(r, "raw", None), dict):
                errors.append(f"{fn}: rule is not a mapping")
                rejected += 1
                continue
            missing = [k for k in REQUIRED if not getattr(r, k, None)]
            if missing:
                errors.append(f"{fn}: rule {r.id or '?'} missing {','.join(missing)}")
                rejected += 1
                continue
            if r.severity not in SEVERITIES:
                errors.append(f"{fn}: rule {r.id} bad severity {r.severity!r}")
                rejected += 1
                continue
            if r.id in seen:
                errors.append(f"{fn}: duplicate rule id {r.id} (first seen in {seen[r.id]})")
                if r.id not in duplicate_ids:
                    duplicate_ids.append(r.id)
                rejected += 1
                continue
            verrs, vwarns = _validate_rule(r, fn)
            warnings.extend(vwarns)
            if verrs:
                errors.extend(verrs)
                rejected += 1
                continue
            seen[r.id] = fn
            rules.append(r)
    if inventory is not None:
        inventory.update({"files_seen": files_seen, "rules_loaded": len(rules),
                          "rules_rejected": rejected, "files_failed": files_failed,
                          "duplicate_ids": sorted(duplicate_ids),
                          "errors": list(errors), "warnings": list(warnings)})
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
