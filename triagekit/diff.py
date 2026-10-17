"""Diff two analysis.json reports. Surfaces what an update actually changed."""
from __future__ import annotations

import re

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Keys must match the manifest attribute names emitted in report["flags"].
# Getting this wrong makes every flag change silently invisible, so every
# FLAG_SPEC key must be watched; checked on every diff() against the
# manifest module's own spec.
WATCHED_FLAGS = ["debuggable", "allowBackup", "usesCleartextTraffic",
                 "requestLegacyExternalStorage", "testOnly", "extractNativeLibs",
                 "networkSecurityConfig", "hasFragileUserData", "fullBackupContent",
                 "dataExtractionRules", "largeHeap", "usesNonSdkApi"]


def _assert_flag_keys() -> None:
    from .manifest import FLAG_SPEC
    watched = set(WATCHED_FLAGS)
    unknown = [k for k in WATCHED_FLAGS if k not in FLAG_SPEC]
    unwatched = [k for k in FLAG_SPEC if k not in watched]
    if unknown or unwatched:
        raise RuntimeError(
            "diff.py WATCHED_FLAGS drifted from manifest.FLAG_SPEC: "
            f"unknown={unknown} unwatched={unwatched}")


def _set(xs) -> set:
    return {x if isinstance(x, str) else repr(x) for x in (xs or [])}


def _comps(r) -> dict:
    return {c["name"]: c for c in r.get("components", [])}


# ------------------------------------------------- coverage-aware comparison
# A disappearing finding is only "confirmed remediation" when the stage that
# produced it ran AND completed in both runs, the rule stayed in the loaded
# inventory, and the artifact actually changed. Anything else is reported as
# unconfirmed with a reason, so a partial or regressed run can never be read
# as a fix.

_STAGE_FOR_KIND = {"manifest": "manifest", "regex": "regex",
                   "smali-taint": "smali-taint", "reachability": "reachability"}
_STATUS_ORDER = {"complete": 2, "partial": 1, "not_analysed": 0}
_COMPARED_FIELDS = ("severity", "title", "component", "file", "evidence")

# evidence.py appends `-N` to duplicate-basis finding ids; such ids are not
# stable identities, so a removal claim about one is never confirmable.
_ID_SUFFIX_RE = re.compile(r"^[0-9a-f]{16}-\d+$")


def _stage_key(f: dict) -> str:
    detail = f.get("detail") or {}
    if any(k in detail for k in ("file_offset", "encoding",
                                 "source_artifact_sha256", "classification")):
        return "native"
    return _STAGE_FOR_KIND.get(str(f.get("kind", "")), "")


def _stage_records(r: dict) -> dict:
    stages = (r.get("analysis") or {}).get("stages") or []
    return {str(s.get("stage")): s for s in stages if isinstance(s, dict)}


def _rich_findings(r: dict) -> list[dict]:
    out = []
    for f in r.get("findings") or []:
        fid = f.get("finding_id")
        out.append({
            "key": str(fid) if fid else "legacy:" + "|".join(
                (str(f.get("rule", "")), str(f.get("component", "")),
                 str(f.get("title", "")))),
            "legacy_key": (f.get("rule"), f.get("component", ""), f.get("title", "")),
            "has_id": bool(fid),
            "rule": f.get("rule"),
            "component": f.get("component", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity"),
            "file": f.get("file", ""),
            "evidence": f.get("evidence", ""),
            "kind": f.get("kind", ""),
            "detail": f.get("detail") or {},
        })
    return out


def _match_findings(old_list: list, new_list: list):
    """Pair findings by stable id first, then by legacy (rule, component, title).

    The legacy fallback only pairs findings when at least one side lacks a
    stable id (pre-EV-01 reports). With ids on both sides a non-matching id
    means "different finding" — re-pairing via the coarse tuple would hide
    a removal behind the surviving collided twin.
    """
    matched_old: set[int] = set()
    matched_new: set[int] = set()
    pairs = []
    for oi, o in enumerate(old_list):
        nxt = next((i for i, n in enumerate(new_list)
                    if i not in matched_new and n["key"] == o["key"]), None)
        if nxt is None:
            nxt = next((i for i, n in enumerate(new_list)
                        if i not in matched_new and n["legacy_key"] == o["legacy_key"]
                        and not (o["has_id"] and n["has_id"])),
                       None)
        if nxt is None:
            continue
        matched_old.add(oi)
        matched_new.add(nxt)
        pairs.append((o, new_list[nxt]))
    removed = [o for i, o in enumerate(old_list) if i not in matched_old]
    added = [n for i, n in enumerate(new_list) if i not in matched_new]
    return pairs, removed, added


def _inventory_issue(r: dict, rule, side: str) -> str:
    inv = r.get("rule_inventory") or {}
    texts: list[str] = []
    for key in ("errors", "rules_rejected", "duplicate_ids"):
        v = inv.get(key) or []
        if not isinstance(v, (list, tuple, set)):
            v = [v]
        texts += [str(x) for x in v]
    for t in texts:
        if rule and str(rule) in t:
            return f"{side} run: rule {rule} not cleanly loaded ({t})"
    failed = inv.get("files_failed")
    if failed:
        return f"{side} run: {failed} rule file(s) failed to load; coverage incomplete"
    return ""


def _ambiguous_id(entry: dict) -> bool:
    """True when the id carries evidence.py's duplicate-basis `-N` suffix."""
    return bool(entry.get("has_id")) and bool(
        _ID_SUFFIX_RE.match(str(entry.get("key") or "")))


def _remediation(old: dict, new: dict, o: dict) -> tuple[bool, str]:
    if _ambiguous_id(o):
        return False, ("ambiguous finding identity (duplicate basis in the old "
                       "run); removal cannot be confirmed")
    old_pkg, new_pkg = old.get("package"), new.get("package")
    if old_pkg and new_pkg and old_pkg != new_pkg:
        return False, (f"package identity changed ({old_pkg} -> {new_pkg}); "
                       "a cross-app diff cannot confirm remediation")
    old_sha, new_sha = old.get("apk_sha256"), new.get("apk_sha256")
    if old_sha and new_sha and old_sha == new_sha:
        return False, ("artifact hash unchanged between runs; disappearance may be "
                       "nondeterministic rather than remediation")
    stage = _stage_key(o)
    old_stages, new_stages = _stage_records(old), _stage_records(new)
    if not old_stages and not new_stages:
        return False, "no per-stage coverage recorded in either run; cannot confirm remediation"
    for side, recs in (("old", old_stages), ("new", new_stages)):
        s = recs.get(stage) if stage else None
        if stage and not s:
            return False, f"{side} run: {stage} stage not recorded; coverage unknown"
        if stage and not (s.get("ran") and s.get("complete")):
            reason = s.get("reason") or "stage did not run"
            return False, f"{side} run: {stage} stage incomplete ({reason})"
    if not stage:
        for side, rep in (("old", old), ("new", new)):
            status = (rep.get("analysis") or {}).get("status")
            if status and status != "complete":
                return False, f"{side} run analysis status is {status}; coverage incomplete"
    issue = (_inventory_issue(new, o.get("rule"), "new")
             or _inventory_issue(old, o.get("rule"), "old"))
    if issue:
        return False, issue
    return True, (f"{stage or 'analysis'} stage complete in both runs; "
                  f"rule loaded in both")


def _display_id(entry: dict) -> str:
    key = entry["key"]
    return key[len("legacy:"):] if key.startswith("legacy:") else key


def _finding_changes(old: dict, new: dict) -> dict:
    old_list, new_list = _rich_findings(old), _rich_findings(new)
    pairs, gone, came = _match_findings(old_list, new_list)

    def _has_ids(lst):
        return bool(lst) and all(x["has_id"] for x in lst)

    matched_by = "finding_id" if _has_ids(old_list) and _has_ids(new_list) else "legacy-tuple"

    changed = []
    for o, n in pairs:
        fields = [k for k in _COMPARED_FIELDS if o.get(k) != n.get(k)]
        if fields:
            changed.append({"id": _display_id(n), "fields": fields})

    removed = []
    for o in gone:
        ok, reason = _remediation(old, new, o)
        removed.append({"id": _display_id(o), "rule": o["rule"],
                        "component": o["component"], "title": o["title"],
                        "remediation_confirmed": ok, "reason": reason})
    removed.sort(key=lambda x: x["id"])
    added = sorted(({"id": _display_id(n), "rule": n["rule"],
                     "component": n["component"], "title": n["title"]}
                    for n in came), key=lambda x: x["id"])
    changed.sort(key=lambda x: x["id"])
    return {
        "matched_by": matched_by,
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": len(pairs) - len(changed),
        "legacy_new": sorted({n["legacy_key"] for n in came}),
        "legacy_gone": sorted({o["legacy_key"] for o in gone}),
    }


def _coverage_change(old: dict, new: dict, finding_changes: dict) -> dict:
    oa = old.get("analysis") or {}
    na = new.get("analysis") or {}
    o_status, n_status = oa.get("status"), na.get("status")
    ostages, nstages = _stage_records(old), _stage_records(new)
    stage_changes = []
    for name in sorted(set(ostages) | set(nstages)):
        o, n = ostages.get(name), nstages.get(name)
        o_ok = bool(o and o.get("ran") and o.get("complete"))
        n_ok = bool(n and n.get("ran") and n.get("complete"))
        if o_ok != n_ok or (o is None) != (n is None):
            stage_changes.append({"stage": name, "from": o_ok, "to": n_ok})
    regressed = bool(o_status is not None and n_status is not None
                     and _STATUS_ORDER.get(n_status, -1) < _STATUS_ORDER.get(o_status, -1))
    removed = finding_changes["removed"]
    unconfirmed = [r for r in removed if not r["remediation_confirmed"]]
    if regressed and removed:
        notice = (f"coverage regressed and {len(unconfirmed)} of {len(removed)} "
                  f"disappeared finding(s) are NOT confirmed remediation")
    elif regressed:
        notice = ("analysis coverage regressed compared to the old run; "
                  "negative results are inconclusive")
    elif unconfirmed:
        notice = (f"{len(unconfirmed)} of {len(removed)} disappeared finding(s) "
                  f"are NOT confirmed remediation")
    elif removed:
        notice = (f"all {len(removed)} disappeared finding(s) confirmed against "
                  "complete coverage in both runs")
    else:
        notice = None
    return {
        "old_status": o_status,
        "new_status": n_status,
        "regressed": regressed,
        "stage_changes": stage_changes,
        "blind_spots_delta": len(new.get("blind_spots") or []) - len(old.get("blind_spots") or []),
        "notice": notice,
    }


def _rule_inventory_change(old: dict, new: dict) -> dict:
    oi = old.get("rule_inventory") or {}
    ni = new.get("rule_inventory") or {}
    o_errs = [str(e) for e in (oi.get("errors") or [])]
    n_errs = [str(e) for e in (ni.get("errors") or [])]
    changed = (oi.get("rules_loaded") != ni.get("rules_loaded")
               or o_errs != n_errs
               or bool(oi.get("files_failed")) != bool(ni.get("files_failed")))
    return {"changed": changed,
            "old_rules_loaded": oi.get("rules_loaded"),
            "new_rules_loaded": ni.get("rules_loaded"),
            "old_errors": o_errs, "new_errors": n_errs}


def _artifact_change(old: dict, new: dict) -> dict:
    o, n = old.get("apk_sha256"), new.get("apk_sha256")
    return {"old_sha256": o, "new_sha256": n, "changed": bool(o and n and o != n)}


def _analysis_status_change(old: dict, new: dict) -> dict:
    o = (old.get("analysis") or {}).get("status")
    n = (new.get("analysis") or {}).get("status")
    regressed = bool(o is not None and n is not None
                     and _STATUS_ORDER.get(n, -1) < _STATUS_ORDER.get(o, -1))
    return {"from": o, "to": n, "regressed": regressed}


def diff(old: dict, new: dict) -> dict:
    _assert_flag_keys()
    oc, nc = _comps(old), _comps(new)
    added = sorted(set(nc) - set(oc))
    removed = sorted(set(oc) - set(nc))

    export_added = [n for n in added if nc[n].get("exported")]
    export_removed = [n for n in removed if oc[n].get("exported")]
    export_state = [
        {"name": n, "from": bool(oc[n].get("exported")), "to": bool(nc[n].get("exported"))}
        for n in sorted(set(oc) & set(nc))
        if bool(oc[n].get("exported")) != bool(nc[n].get("exported"))
    ]
    perms_added = sorted(_set(new.get("uses_permissions")) - _set(old.get("uses_permissions")))
    perms_removed = sorted(_set(old.get("uses_permissions")) - _set(new.get("uses_permissions")))

    def _schemes(r):
        return _set([c.get("scheme") for c in r.get("custom_schemes", [])] +
                    [a.get("host") for a in r.get("app_links", [])])

    scheme_added = sorted(_schemes(new) - _schemes(old))
    scheme_removed = sorted(_schemes(old) - _schemes(new))

    fc = _finding_changes(old, new)
    f_new = fc["legacy_new"]
    f_gone = fc["legacy_gone"]

    sig_old = (old.get("signature") or {}).get("sha256")
    sig_new = (new.get("signature") or {}).get("sha256")

    risk: list[str] = []
    if old.get("package") and new.get("package") and old["package"] != new["package"]:
        risk.append(f"PACKAGE CHANGED — {old['package']} -> {new['package']}; "
                    "this is not an update of the same app")
    if export_added:
        risk.append(f"{len(export_added)} new exported component(s): {', '.join(export_added[:6])}")
    for s in export_state:
        risk.append(f"component {s['name']} exported {s['from']} -> {s['to']}")
    if perms_added:
        risk.append(f"{len(perms_added)} new permission(s): {', '.join(perms_added[:10])}")
    if scheme_added:
        risk.append(f"new deep-link scheme/host: {', '.join(scheme_added[:6])}")
    if sig_old and sig_new and sig_old != sig_new:
        risk.append("SIGNING CERTIFICATE CHANGED — verify the distribution channel before installing")
    if old.get("target_sdk") != new.get("target_sdk"):
        risk.append(f"targetSdk {old.get('target_sdk')} -> {new.get('target_sdk')}")
    for k in WATCHED_FLAGS:
        o = (old.get("flags") or {}).get(k)
        n = (new.get("flags") or {}).get(k)
        if o != n and (o is not None or n is not None):
            risk.append(f"flag {k}: {o} -> {n}")

    return {
        "old": {"package": old.get("package"), "version_name": old.get("version_name"),
                "version_code": old.get("version_code"), "sha256": old.get("apk_sha256"),
                "target_sdk": old.get("target_sdk")},
        "new": {"package": new.get("package"), "version_name": new.get("version_name"),
                "version_code": new.get("version_code"), "sha256": new.get("apk_sha256"),
                "target_sdk": new.get("target_sdk")},
        "components_added": added,
        "components_removed": removed,
        "exported_added": export_added,
        "exported_removed": export_removed,
        "export_state_changed": export_state,
        "permissions_added": perms_added,
        "permissions_removed": perms_removed,
        "schemes_added": scheme_added,
        "schemes_removed": scheme_removed,
        "findings_new": [{"rule": a, "component": b, "title": c} for a, b, c in f_new],
        "findings_resolved": [{"rule": a, "component": b, "title": c} for a, b, c in f_gone],
        "signer_changed": bool(sig_old and sig_new and sig_old != sig_new),
        "risk_signals": risk,
        "finding_changes": fc,
        "coverage_change": _coverage_change(old, new, fc),
        "rule_inventory_change": _rule_inventory_change(old, new),
        "artifact_change": _artifact_change(old, new),
        "analysis_status_change": _analysis_status_change(old, new),
    }


def render(d: dict) -> str:
    L = [f"# Release diff — {d['old'].get('package')} "
         f"{d['old'].get('version_name')} → {d['new'].get('version_name')}", ""]
    if d["risk_signals"]:
        L += ["## Risk signals", ""] + [f"- ⚠️ {x}" for x in d["risk_signals"]] + [""]
    for title, key in (("Components added", "components_added"),
                       ("Components removed", "components_removed"),
                       ("Exported components added", "exported_added"),
                       ("Exported components removed", "exported_removed"),
                       ("Permissions added", "permissions_added"),
                       ("Permissions removed", "permissions_removed"),
                       ("Schemes/hosts added", "schemes_added"),
                       ("Schemes/hosts removed", "schemes_removed")):
        v = d.get(key) or []
        L.append(f"## {title} ({len(v)})")
        L.append("")
        L += ([f"- `{x}`" for x in v] if v else ["_none_"])
        L.append("")
    L.append(f"## Findings new ({len(d['findings_new'])})")
    L.append("")
    L += ([f"- `{x['rule']}` {x['title']} `{x['component']}`" for x in d["findings_new"]]
          or ["_none_"])
    L.append("")
    L.append(f"## Findings resolved ({len(d['findings_resolved'])})")
    L.append("")
    L += ([f"- `{x['rule']}` {x['title']} `{x['component']}`" for x in d["findings_resolved"]]
          or ["_none_"])
    L.append("")
    fc = d.get("finding_changes")
    if fc:
        L.append(f"## Findings added ({len(fc['added'])})")
        L.append("")
        L += ([f"- `{x['rule']}` {x['title']} `{x['component']}` ({x['id']})"
               for x in fc["added"]] or ["_none_"])
        L.append("")
        L.append(f"## Findings removed ({len(fc['removed'])})")
        L.append("")
        for x in fc["removed"]:
            status = ("confirmed remediation" if x["remediation_confirmed"]
                      else f"NOT confirmed remediation — {x['reason']}")
            L.append(f"- `{x['rule']}` {x['title']} `{x['component']}` — {status}")
        if not fc["removed"]:
            L.append("_none_")
        L.append("")
        if fc["changed"]:
            L.append(f"## Findings changed ({len(fc['changed'])})")
            L.append("")
            L += [f"- `{x['id']}` fields: {', '.join(x['fields'])}" for x in fc["changed"]]
            L.append("")
        cc = d.get("coverage_change")
        if cc:
            L.append("## Coverage change")
            L.append("")
            L.append(f"- analysis status: `{cc['old_status']}` → `{cc['new_status']}`"
                     + (" (REGRESSED)" if cc["regressed"] else ""))
            for s in cc["stage_changes"]:
                L.append(f"- stage `{s['stage']}`: complete {s['from']} → {s['to']}")
            if cc["notice"]:
                L.append(f"- ⚠️ {cc['notice']}")
            L.append("")
    return "\n".join(L)
