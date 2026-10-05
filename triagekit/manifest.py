"""AndroidManifest.xml parsing: components, security flags, deep links.

Works on the decoded (human-readable XML) form that apktool produces, which is
what we control and what avoids reimplementing binary AXML.
"""
from __future__ import annotations

import os
import re
from xml.etree import ElementTree as ET

from .utils import fq

NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# application-level security flags we care about
FLAG_SPEC = {
    "debuggable": ("boolean", "Enables JDWP; any app can attach a debugger to the process."),
    "allowBackup": ("tri-state", "adb backup can extract app data unless explicitly excluded."),
    "usesCleartextTraffic": ("boolean", "Permits plain HTTP from the app."),
    "requestLegacyExternalStorage": ("boolean", "Opt-in to legacy unscoped storage on Android 10."),
    "testOnly": ("boolean", "Marked testOnly; installable but not shippable."),
    "extractNativeLibs": ("boolean", "If false, native libs are loaded directly from the APK."),
    "networkSecurityConfig": ("string", "Points at a Network Security Configuration XML."),
    "hasFragileUserData": ("boolean", "Data may be restored onto a different device."),
    "fullBackupContent": ("string", "Legacy backup inclusion rules."),
    "dataExtractionRules": ("string", "Android 12+ backup rules."),
    "largeHeap": ("boolean", "Requests a large heap; not a vuln, recorded for completeness."),
    "usesNonSdkApi": ("boolean", "Non-SDK interface usage was declared."),
}

# permissions that deserve a louder note than "the app asked for this"
DANGEROUS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "BODY_SENSORS", "ACTIVITY_RECOGNITION",
    "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "REQUEST_DELETE_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
    "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
    "REQUEST_SMS_FINANCIAL_TRANSACTIONS", "WRITE_SETTINGS",
}


def _attr(el, name: str):
    return el.get(NS + name)


def _b(el, name: str):
    v = _attr(el, name)
    return None if v is None else str(v).lower() == "true"


def _intent_filters(el) -> list[dict]:
    out = []
    for f in el.findall("intent-filter"):
        actions = [a.get(NS + "name") for a in f.findall("action") if a.get(NS + "name")]
        cats = [c.get(NS + "name") for c in f.findall("category") if c.get(NS + "name")]
        data = []
        for d in f.findall("data"):
            data.append({
                k: d.get(NS + k) for k in
                ("scheme", "host", "port", "path", "pathPrefix", "pathPattern",
                 "pathAdvancedPattern", "mimeType")
                if d.get(NS + k) is not None
            })
        if _b(f, "autoVerify"):
            actions = actions
        out.append({"actions": actions, "categories": cats, "data": data,
                    "autoVerify": bool(_b(f, "autoVerify"))})
    return out


def parse(manifest_path: str) -> dict:
    """Return {package, version*, application:{flags}, components, permissions,
    uses_permissions, defined_permissions, deeplinks, app_links, custom_schemes}."""
    empty = {
        "package": "", "version_name": "", "version_code": "",
        "min_sdk": "", "target_sdk": "", "application": {}, "components": [],
        "permissions": [], "uses_permissions": [], "defined_permissions": [],
        "deeplinks": [], "app_links": [], "custom_schemes": [],
        "meta_data": [],
        "parse_error": None,
    }
    if not os.path.isfile(manifest_path):
        empty["parse_error"] = f"manifest not found: {manifest_path}"
        return empty
    try:
        root = ET.parse(manifest_path).getroot()
    except ET.ParseError as e:
        empty["parse_error"] = f"manifest parse error: {e}"
        return empty

    pkg = root.get("package", "")
    empty["package"] = pkg
    empty["version_name"] = root.get(NS + "versionName") or ""
    empty["version_code"] = root.get(NS + "versionCode") or ""
    for k, out in (("minSdkVersion", "min_sdk"), ("targetSdkVersion", "target_sdk")):
        el = root.find("uses-sdk")
        if el is not None and el.get(NS + k):
            empty[out] = el.get(NS + k)

    for p in root.findall("uses-permission"):
        n = p.get(NS + "name")
        if n:
            empty["uses_permissions"].append(n)
    for p in root.findall("permission"):
        n = p.get(NS + "name")
        if n:
            info = {"name": n, "protection_level": p.get(NS + "protectionLevel") or ""}
            empty["defined_permissions"].append(info)

    app = root.find("application")
    if app is None:
        return empty

    for fname, (kind, _desc) in FLAG_SPEC.items():
        if fname not in FLAG_SPEC:
            continue
        if kind == "boolean":
            v = _b(app, fname)
            if v is not None:
                empty["application"][fname] = v
        elif kind == "tri-state":
            v = _attr(app, fname)
            if v is not None:
                empty["application"][fname] = v
        else:
            v = _attr(app, fname)
            if v is not None:
                empty["application"][fname] = v

    for md in root.iter("meta-data"):
        n = md.get(NS + "name") or ""
        v = md.get(NS + "value") or md.get(NS + "resource") or ""
        if n:
            empty["meta_data"].append({"name": n, "value": str(v)})

    for tag in COMPONENT_TAGS:
        for el in app.iter(tag):
            name = fq(_attr(el, "name") or "", pkg)
            exported = _b(el, "exported")
            filters = _intent_filters(el)
            if exported is None and filters:
                # pre-API-31 default: an intent-filter implies exported
                exported = True
                implicit = True
            else:
                implicit = False
            comp = {
                "type": tag,
                "name": name,
                "exported": exported,
                "exported_implicit": implicit,
                "permission": _attr(el, "permission"),
                "read_permission": _attr(el, "readPermission"),
                "write_permission": _attr(el, "writePermission"),
                "grant_uri_permissions": _b(el, "grantUriPermissions"),
                "authorities": _attr(el, "authorities"),
                "enabled": _b(el, "enabled"),
                "intent_filters": filters,
            }
            empty["components"].append(comp)

            for f in filters:
                for d in f["data"]:
                    scheme = d.get("scheme")
                    if not scheme:
                        continue
                    host = d.get("host")
                    # One <data> element is one link. Do NOT merge across elements:
                    # <data scheme="app" host="oauth"/> and <data scheme="https"
                    # host="app.example.com"/> are two different link targets, and
                    # merging them produces a test command that targets neither.
                    if scheme in ("http", "https"):
                        empty["app_links"].append(
                            {"component": name, "scheme": scheme, "host": host,
                             "auto_verify": f["autoVerify"], "actions": f["actions"]})
                    else:
                        empty["custom_schemes"].append(
                            {"component": name, "scheme": scheme, "host": host,
                             "actions": f["actions"]})
                if "android.intent.action.VIEW" in f["actions"]:
                    for d in f["data"]:
                        if not d.get("scheme"):
                            continue
                        empty["deeplinks"].append({
                            "component": name,
                            "scheme": d["scheme"],
                            "host": d.get("host"),
                            "paths": [d[k] for k in ("path", "pathPrefix", "pathPattern")
                                      if d.get(k)],
                            "auto_verify": f["autoVerify"],
                        })

    # de-duplicate deep links
    seen, uniq = set(), []
    for dl in empty["deeplinks"]:
        k = json_key(dl)
        if k not in seen:
            seen.add(k)
            uniq.append(dl)
    empty["deeplinks"] = uniq
    return empty


def json_key(o) -> str:
    import json
    return json.dumps(o, sort_keys=True)


def _nsc_from_tree(root) -> dict:
    """Pull the interesting bits out of a <network-security-config> element."""
    domains = []
    for tag, kind in (("base-config", "base-config"), ("debug-overrides", "debug-overrides")):
        for el in root.findall(tag):
            domains.append({
                "kind": kind,
                "cleartext": el.get("cleartextTrafficPermitted"),
                "trust_anchors": [e.get("src") for e in el.findall("trust-anchors/anchors")],
                "certificates": [e.get("src") for e in el.findall("certificates")],
            })
    for dom in root.findall("domain-config"):
        domains.append({
            "kind": "domain-config",
            "domain": dom.findtext("domain"),
            "cleartext": dom.get("cleartextTrafficPermitted"),
            "pinning": dom.findtext("pin-set") is not None,
            "trust_anchors": [e.get("src") for e in dom.findall("trust-anchors/anchors")],
        })
    return {
        "domains": domains,
        "has_debug_overrides": root.find("debug-overrides") is not None,
        "pins": [p.text for p in root.iter("pin") if p.text],
    }


def find_network_security_config(apk: str, max_files: int = 2000) -> list[dict]:
    """Locate the NSC by CONTENT, not by filename.

    Modern aapt2 shortens resource paths (F-Droid ships 850 files named
    res/-1.xml, res/-5.xml, ...), so the manifest's @0x7f150006 cannot be
    resolved to a path without a full resources.arsc parse. Instead: parse every
    res/*.xml as AXML and keep the ones whose root element is
    <network-security-config>. ~850 tiny files is well under a second and it
    survives path obfuscation completely.
    """
    import zipfile
    from . import axml
    out: list[dict] = []
    # AXML string pools are UTF-16LE or UTF-8, so a naive ASCII byte search for
    # the tag name never matches. Pre-filter on both encodings.
    needles = (b"network-security-config",
               "network-security-config".encode("utf-16-le"))
    try:
        with zipfile.ZipFile(apk) as z:
            names = [n for n in z.namelist()
                     if n.startswith("res/") and n.endswith(".xml")]
            for n in names[:max_files]:
                try:
                    raw = z.read(n)
                except Exception:  # noqa: BLE001
                    continue
                if not any(x in raw for x in needles):
                    continue
                try:
                    root = axml.parse_bytes(raw)
                except Exception:  # noqa: BLE001
                    continue
                if root.tag != "network-security-config":
                    continue
                rec = {"file": n, "source": "content-scan (resource paths are obfuscated)"}
                rec.update(_nsc_from_tree(root))
                out.append(rec)
    except zipfile.BadZipFile:
        return []
    return out


def read_network_security_config(decoded_dir: str) -> list[dict]:
    """Parse every res/xml/network_security_config.xml (and variants)."""
    out = []
    xml_dir = os.path.join(decoded_dir, "res", "xml")
    if not os.path.isdir(xml_dir):
        return out
    for fn in sorted(os.listdir(xml_dir)):
        if not re.match(r"network_security_config.*\.xml$", fn):
            continue
        p = os.path.join(xml_dir, fn)
        try:
            root = ET.parse(p).getroot()
        except ET.ParseError:
            out.append({"file": f"res/xml/{fn}", "parse_error": True, "raw": open(p, encoding="utf-8", errors="replace").read()})
            continue
        rec = {"file": f"res/xml/{fn}", "source": "apktool decode"}
        rec.update(_nsc_from_tree(root))
        out.append(rec)
    return out


def read_file_provider_paths(decoded_dir: str) -> list[dict]:
    """Parse res/xml/*paths*.xml (FileProvider path grants).

    Returns [{file, entries:[{tag, name, path}], risky:bool}].
    Risky = root-path or path="."/""/"/" which exposes far more than intended.
    """
    out = []
    xml_dir = os.path.join(decoded_dir, "res", "xml")
    if not os.path.isdir(xml_dir):
        return out
    for fn in sorted(os.listdir(xml_dir)):
        if not re.search(r"paths?\.xml$", fn):
            continue
        p = os.path.join(xml_dir, fn)
        try:
            root = ET.parse(p).getroot()
        except ET.ParseError:
            continue
        entries = []
        for el in root.iter():
            if el.tag in ("paths",):
                continue
            path = el.get("path") or ""
            entries.append({"tag": el.tag, "name": el.get("name") or "",
                            "path": path})
        risky = any(e["tag"] == "root-path" or e["path"] in (".", "", "/")
                    for e in entries)
        out.append({"file": f"res/xml/{fn}", "entries": entries,
                    "risky": risky})
    return out
