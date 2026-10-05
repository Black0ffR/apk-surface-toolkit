"""Diff two analysis.json reports. Surfaces what an update actually changed."""
from __future__ import annotations

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Keys must match the manifest attribute names emitted in report["flags"].
# Getting this wrong makes every flag change silently invisible, so it is
# asserted at import time against the manifest module's own spec.
WATCHED_FLAGS = ["debuggable", "allowBackup", "usesCleartextTraffic",
                 "requestLegacyExternalStorage", "networkSecurityConfig",
                 "testOnly", "dataExtractionRules"]


def _assert_flag_keys() -> None:
    from .manifest import FLAG_SPEC
    unknown = [k for k in WATCHED_FLAGS if k not in FLAG_SPEC]
    if unknown:
        raise RuntimeError(f"diff.py watches flags that do not exist in FLAG_SPEC: {unknown}")


def _set(xs) -> set:
    return {x if isinstance(x, str) else repr(x) for x in (xs or [])}


def _comps(r) -> dict:
    return {c["name"]: c for c in r.get("components", [])}


def _findings(r) -> set:
    return {(f.get("rule"), f.get("component", ""), f.get("title", "")) for f in r.get("findings", [])}


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

    of, nf = _findings(old), _findings(new)
    f_new = sorted(nf - of)
    f_gone = sorted(of - nf)

    sig_old = (old.get("signature") or {}).get("sha256")
    sig_new = (new.get("signature") or {}).get("sha256")

    risk: list[str] = []
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
    return "\n".join(L)
