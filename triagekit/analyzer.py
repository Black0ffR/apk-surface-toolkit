"""Analysis orchestration: decode -> parse -> structural -> rules -> findings."""
from __future__ import annotations

import os
import re

from . import apktools, manifest as mf, rules as R
from .utils import now, sha256, workspace, write_json

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


# --------------------------------------------------------------- rule checks
def _ctx(man: dict) -> dict:
    return {"package": man.get("package", ""), "version_name": man.get("version_name", "")}


def load_platform_perms(path: str) -> set:
    """Known android.permission.* names.

    A component legitimately references platform permissions it never declares
    (BIND_JOB_SERVICE, DUMP, MANAGE_DOCUMENTS...). Reporting those as forged
    permissions is pure noise -- so a name is only suspicious when it is not a
    real platform permission. This list is a snapshot; an unknown new platform
    permission produces a false positive that this file then fixes.
    """
    out: set = set()
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                out.add(line)
    return out


def classify_undeclared(perm: str, defined: set, platform: set, pkg: str) -> tuple[str, str]:
    """-> (severity_override_or_empty, reason). Empty = not a finding."""
    if perm in defined:
        return "", ""
    if perm.startswith("android."):
        if perm.split(".")[-1] in platform:
            return "", ""            # real platform permission, not the app's job to declare
        return "medium", ("names an android.permission.* that is not a known platform "
                          "permission and is not declared here; any app can define it")
    if pkg and perm.startswith(pkg):
        return "high", ("in this app's own namespace but never declared - almost certainly a "
                        "typo, a removed declaration, or an inherited name from an old build")
    return "low", "third-party permission string this app never declares"


def _is_launcher(comp: dict) -> bool:
    """A MAIN + LAUNCHER activity is the app icon; it MUST be exported."""
    for f in comp.get("intent_filters", []):
        acts, cats = f.get("actions", []), f.get("categories", [])
        if ("android.intent.action.MAIN" in acts
                and "android.intent.category.LAUNCHER" in cats):
            return True
    return False


def check_manifest(rules: list[R.Rule], man: dict, nsc: list[dict],
                   platform: set | None = None,
                   file_paths: list | None = None,
                   sig: dict | None = None,
                   backup_rules: list | None = None) -> list[dict]:
    out: list[dict] = []
    platform = platform or set()
    defined = {p["name"] for p in man.get("defined_permissions", [])}
    pkg = man.get("package", "")
    comps = man.get("components", [])

    for r in rules:
        c = r.check
        if c == "unprotected_exported":
            for comp in comps:
                if not comp.get("exported"):
                    continue
                if _is_launcher(comp):
                    continue      # the launcher icon must be exported; not a finding
                if comp.get("permission") or comp.get("read_permission"):
                    continue
                out.append(R.finding(
                    r, component=comp["name"],
                    evidence=(f'{comp["type"]} exported with no permission'
                              + (" (implicit via intent-filter)" if comp["exported_implicit"] else "")),
                    extra={"type": comp["type"]}))
        elif c == "undeclared_permission":
            for comp in comps:
                for pk in ("permission", "read_permission", "write_permission"):
                    val = comp.get(pk)
                    if not val:
                        continue
                    sev, reason = classify_undeclared(val, defined, platform, pkg)
                    if not sev:
                        continue
                    f = R.finding(
                        r, component=comp["name"],
                        evidence=f'{pk}="{val}" - {reason}',
                        extra={"permission": val, "attribute": pk})
                    # preserve the rule's ordering intent, but let classification override
                    if sev != r.severity:
                        f["severity"] = sev
                        f["severity_adjusted"] = f"{r.severity} -> {sev}"
                    out.append(f)
        elif c == "provider_exposed":
            # A FileProvider is exported on purpose: its security comes from
            # res/xml/file_paths.xml plus grantUriPermissions, not from a
            # manifest-level permission. Reporting every FileProvider as a leak
            # buries the real finding (verified: 4/4 high findings on F-Droid
            # were FileProvider-family classes).
            file_suffixes = [x.lower() for x in r.params.get(
                "file_provider_classes", ["FileProvider"])]
            for comp in comps:
                if comp["type"] != "provider":
                    continue
                cls = comp["name"].rsplit(".", 1)[-1].lower()
                is_file_provider = any(cls.endswith(s) for s in file_suffixes)
                if comp.get("exported") and not (comp.get("permission") or comp.get("read_permission")):
                    if is_file_provider:
                        out.append(R.finding(
                            r, component=comp["name"],
                            evidence="FileProvider-style provider: exported by design, secured by "
                                     "res/xml/*file_paths*.xml + grantUriPermissions. Verify the "
                                     "paths file, not the manifest.",
                            extra={"authorities": comp.get("authorities"),
                                   "class": "file_provider"}))
                        out[-1]["severity"] = r.params.get("file_provider_severity", "info")
                    else:
                        out.append(R.finding(r, component=comp["name"],
                                             evidence='exported provider with no read permission',
                                             extra={"authorities": comp.get("authorities")}))
                if (comp.get("grant_uri_permissions") and not comp.get("permission")
                        and not is_file_provider):
                    # grantUriPermissions on a NON-exported provider is the
                    # normal, safe FileProvider pattern: the app hands out a
                    # scoped URI deliberately. Only worth a look when the
                    # provider is also exported, where the grant is guessable.
                    f = R.finding(
                        r, component=comp["name"],
                        evidence=("grantUriPermissions=true on an EXPORTED provider with no "
                                 "permission - a granted URI may be reachable by any app"
                                 if comp.get("exported") else
                                 "grantUriPermissions=true on a non-exported provider (scoped "
                                 "grant; check res/xml/*paths*.xml covers only what you expect)"),
                        extra={"authorities": comp.get("authorities"),
                               "exported": bool(comp.get("exported"))})
                    if not comp.get("exported"):
                        f["severity"] = r.params.get("nonexported_grant_severity", "info")
                    out.append(f)
        elif c == "flag":
            key = r.params.get("flag")
            bad = r.params.get("value", True)
            got = man.get("application", {}).get(key)
            if got is None:
                continue
            if (bad is True and got is True) or (str(got).lower() == str(bad).lower()):
                ev = str(got).lower() if isinstance(got, bool) else str(got)
                out.append(R.finding(r, evidence=f'android:{key}="{ev}"',
                                     extra={"flag": key, "value": got}))
        elif c == "nsc":
            for cfg in nsc:
                if r.params.get("want") == "debug_overrides" and cfg.get("has_debug_overrides"):
                    out.append(R.finding(r, file=cfg["file"],
                                         evidence="<debug-overrides> present in shipped config",
                                         extra={"file": cfg["file"]}))
                if r.params.get("want") == "cleartext":
                    for dom in cfg.get("domains", []):
                        if str(dom.get("cleartext", "")).lower() == "true":
                            out.append(R.finding(r, file=cfg["file"],
                                                 evidence=f'<{dom["kind"]} cleartextTrafficPermitted="true">',
                                                 extra={"domain": dom}))
        elif c == "custom_scheme":
            for cs in man.get("custom_schemes", []):
                out.append(R.finding(
                    r, component=cs["component"],
                    evidence=f'scheme="{cs["scheme"]}"' + (f' host="{cs["host"]}"' if cs.get("host") else ""),
                    extra=cs,
                    **{}))
                out[-1]["repro"] = R.fmt_repro(r, {
                    "package": man.get("package", ""), "component": cs["component"],
                    "scheme": cs["scheme"]})
        elif c == "deeplink_unverified":
            for al in man.get("app_links", []):
                if not al.get("auto_verify"):
                    out.append(R.finding(
                        r, component=al["component"],
                        evidence=f'{al["scheme"]}://{al.get("host") or "*"} without android:autoVerify',
                        extra=al,
                        **{}))
        elif c == "dangerous_permission":
            # One aggregated finding. A per-permission finding list is unreadable
            # and buries everything else in the report.
            allowed = set(r.params.get("names", []))
            hits = [p for p in man.get("uses_permissions", [])
                    if p.rsplit(".", 1)[-1].upper() in mf.DANGEROUS
                    and (not allowed or p.rsplit(".", 1)[-1].upper() in allowed)]
            if hits:
                out.append(R.finding(
                    r,
                    evidence=f"{len(hits)} sensitive permission(s): " + ", ".join(hits),
                    extra={"permissions": hits, "count": len(hits)}))
        elif c == "custom_permission_weak":
            for p in man.get("defined_permissions", []):
                pl = (p.get("protection_level") or "").lower()
                if pl in ("normal", "dangerous", "") or pl.startswith("normal"):
                    out.append(R.finding(r, evidence=f'{p["name"]} protectionLevel="{pl or "normal (default)"}"',
                                         extra=p))
        elif c == "paths_traversal":
            for fp in (file_paths or []):
                if fp.get("risky"):
                    detail = ", ".join(
                        f'{e["tag"]} path="{e["path"]}"'
                        for e in fp.get("entries", [])[:6])
                    out.append(R.finding(
                        r, file=fp.get("file", ""),
                        evidence=f'{fp.get("file")} grants broad access: {detail}',
                        extra={"paths": fp}))
        elif c == "meta_data_secret":
            needles = [s.lower() for s in r.params.get(
                "names", ["key", "secret", "token", "password",
                           "firebase", "google-api", "api_key"])]
            for md in man.get("meta_data", []):
                name = str(md.get("name", ""))
                val = str(md.get("value", ""))
                if any(n in name.lower() for n in needles):
                    out.append(R.finding(
                        r, evidence=f'meta-data {name}="{val[:120]}"',
                        extra={"meta": md}))
        elif c == "strandhogg":
            modes = set(r.params.get("modes", ["singleTask", "singleInstance"]))
            for comp in comps:
                if comp.get("type") not in ("activity", "activity-alias"):
                    continue
                if not comp.get("exported"):
                    continue
                aff = (comp.get("task_affinity") or "")
                lm = (comp.get("launch_mode") or "")
                reparent = comp.get("allow_task_reparenting") is True
                if aff and aff != pkg and (lm in modes or reparent):
                    out.append(R.finding(
                        r, component=comp["name"],
                        evidence=(f'{comp["type"]} taskAffinity="{aff}" '
                                  f'launchMode="{lm or "-"}"'
                                  f'{" allowTaskReparenting=true" if reparent else ""}'),
                        extra={"type": comp["type"]}))
        elif c == "tapjacking":
            acts = [c2["name"] for c2 in comps
                    if c2.get("type") in ("activity", "activity-alias")
                    and c2.get("exported")]
            if acts:
                shown = ", ".join(f"`{a}`" for a in acts[:10])
                more = f" +{len(acts) - 10} more" if len(acts) > 10 else ""
                out.append(R.finding(
                    r, evidence=(f"{len(acts)} exported activit(es): "
                                 f"{shown}{more}. Verify overlay handling "
                                 f"(filterTouchesWhenObscured / FLAG_WINDOW_IS_OBSCURED) manually."),
                    extra={"activities": acts[:25], "count": len(acts)}))
        elif c == "sig_verdict":
            s = sig or {}
            if not s.get("ok"):
                continue
            v1 = bool(s.get("v1"))
            v2 = bool(s.get("v2"))
            v3 = bool(s.get("v3"))
            dn = str(s.get("dn", ""))
            if "Android Debug" in dn or "CN=Android Debug" in dn:
                out.append(R.finding(
                    r, evidence=f"signed with debug certificate: {dn[:120]}",
                    extra={"dn": dn}))
            try:
                minsdk = int(str(man.get("min_sdk") or "0"))
            except ValueError:
                minsdk = 0
            if v1 and not (v2 or v3) and minsdk <= 27:
                out.append(R.finding(
                    r, evidence=(f"v1-only signature with minSdk {minsdk or '?'} "
                                 f"(Janus CVE-2017-13156 reachable on API 21-27 via trojanized install)"),
                    extra={"v1": v1, "v2": v2, "v3": v3, "min_sdk": minsdk}))
        elif c == "nsc_hardening":
            want = r.params.get("want", "")
            for cfg in nsc:
                if want == "user_ca":
                    for dom in cfg.get("domains", []):
                        anchors = " ".join(
                            str(x or "") for x in
                            (dom.get("trust_anchors") or []))
                        certs = " ".join(
                            str(x or "") for x in
                            (dom.get("certificates") or []))
                        if "user" in (anchors + " " + certs).lower():
                            out.append(R.finding(
                                r, file=cfg.get("file", ""),
                                evidence=(f'{cfg.get("file")}: user trust anchors in '
                                          f'{dom.get("kind")} (allows user-installed CAs)'),
                                extra={"domain": dom}))
                elif want == "no_pinning":
                    if cfg.get("pins"):
                        continue
                    has_pin = any(d.get("pinning") for d in cfg.get("domains", []))
                    if not has_pin:
                        out.append(R.finding(
                            r, file=cfg.get("file", ""),
                            evidence=(f'{cfg.get("file")}: network security config '
                                      f"present but no <pin-set> (no pinning)"),
                            extra={"file": cfg.get("file")}))
        elif c == "backup_rules":
            for br in (backup_rules or []):
                if br.get("missing"):
                    continue
                if br.get("wide"):
                    inc = ", ".join(
                        f'{i.get("domain")}:{i.get("path") or "*"}'
                        for i in br.get("includes", [])[:5])
                    out.append(R.finding(
                        r, file=br.get("file", ""),
                        evidence=(f'{br.get("file")} backs up broadly '
                                  f'({inc or "full/default"}) with no excludes'),
                        extra={"rules": br}))
        elif c == "risky_flags":
            for flag in r.params.get("flags", []):
                got = man.get("application", {}).get(flag)
                if got is None:
                    continue
                bad = r.params.get("values", {}).get(flag, True)
                if (bad is True and got is True) or (str(got).lower() == str(bad).lower()):
                    out.append(R.finding(
                        r, evidence=f"android:{flag}=\"{str(got).lower()}\"",
                        extra={"flag": flag, "value": got}))
    return out


def _shannon(s: str) -> float:
    """Shannon entropy in bits/char. Random base64 ~6, English ~4."""
    import math
    from collections import Counter
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# Third-party SDKs are out of scope (mobile-pentest: they belong to
# Google/Firebase/Ads, not the target) and dominate scan time (61/65MB in
# the reference APK). Skipped for every regex rule unless it opts back in
# with params.include_vendor=true.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-/+=]{20,}")
_ENT_HINT_RE = re.compile(r"[=:\"']|key|secret|token|password|api[_-]?key|auth",
                          re.I)
VENDOR_PREFIXES = ("smali/android", "smali/androidx",
                   "smali/com/google", "smali/com/googlecode",
                   "smali/kotlin", "smali/kotlinx",
                   "smali/okhttp3", "smali/okio",
                   "smali/javax", "smali/org/apache",
                   "smali/org/json", "smali/dagger",
                   "smali/com/squareup", "smali/io/reactivex")

_URL_RE = re.compile(r"https?://[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}", re.I)
_KEY_RE = re.compile(r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|"
                     r"ghp_[A-Za-z0-9]{36}|sk_live_[A-Za-z0-9]{16,}|"
                     r"xox[baprs]-[A-Za-z0-9\-]{10,})")


def check_native(rules_by_id: dict, apk: str, limit: int = 25) -> list[dict]:
    """Scan lib/**/*.so bytes for URLs + key shapes (no external `strings` needed).

    Reuses AS-0021 (URLs) and AS-0016 (keys) rule metadata when present.
    """
    import zipfile
    out: list[dict] = []
    hits = 0
    try:
        with zipfile.ZipFile(apk) as z:
            names = [n for n in z.namelist()
                     if n.startswith("lib/") and n.endswith(".so")]
            for n in names[:20]:
                try:
                    raw = z.read(n)
                except Exception:
                    continue
                if len(raw) > 8_000_000:
                    raw = raw[:8_000_000]
                text = raw.decode("utf-8", "replace")
                for m in _URL_RE.finditer(text):
                    if "schemas.android.com" in m.group(0) or "w3.org" in m.group(0):
                        continue
                    r = rules_by_id.get("AS-0021")
                    if r is None:
                        break
                    out.append(R.finding(
                        r, file=n,
                        evidence=f"{n}: native URL {m.group(0)[:120]}",
                        extra={"native": True}))
                    hits += 1
                    if hits >= limit:
                        break
                for m in _KEY_RE.finditer(text):
                    r = rules_by_id.get("AS-0016")
                    if r is None:
                        break
                    out.append(R.finding(
                        r, file=n,
                        evidence=f"{n}: native key-shaped token {m.group(0)[:32]}…",
                        extra={"native": True}))
                    hits += 1
                    if hits >= limit:
                        break
                if hits >= limit:
                    break
    except zipfile.BadZipFile:
        pass
    if hits >= limit and out:
        for f in out:
            f.setdefault("detail", {})["truncated"] = True
        out[-1]["evidence"] += f" [truncated at {limit} hits]"
    return out


def check_regex(rules: list[R.Rule], decoded: str, limit: int = 25) -> list[dict]:
    """Scan decoded text for patterns. Skipped entirely for packed samples.

    A rule may restrict itself to specific file extensions via
    params.exts. This matters: a Java-source rule ("checkServerTrusted(") will
    never match smali (".method protected checkServerTrusted(...)V") and vice
    versa, and a rule that silently matches nothing is worse than no rule.

    params.multiline=true reads the whole file with DOTALL (for smali
    const-string + invoke pairs). params.entropy_min=4.5 additionally flags
    high-entropy tokens (>=20 chars) as possible secrets.
    """
    out: list[dict] = []
    if not decoded or not os.path.isdir(decoded):
        return out
    default_exts = {".java", ".smali", ".kt", ".xml", ".json", ".txt", ".js"}
    for r in rules:
        pat = r.params.get("pattern")
        if not pat:
            continue
        flags = re.I | (re.DOTALL if r.params.get("multiline") else 0)
        try:
            rx = re.compile(pat, flags)
        except re.error as e:
            out.append(R.finding(r, evidence=f"bad regex in rule: {e}"))
            continue
        base = os.path.join(decoded, r.params.get("root", "."))
        if not os.path.isdir(base):
            continue
        exts = {e.lower() if e.startswith(".") else "." + e.lower()
                for e in r.params.get("exts", default_exts)}
        ent_min = float(r.params.get("entropy_min", 0) or 0)
        skip_dirs = set(r.params.get("skip_dirs", []))
        # Entropy is for config tokens, not code: scanning 60MB of smali
        # with Shannon per token is what blew the 5-min budget on-phone.
        ent_exts = {".xml", ".json", ".txt", ".properties", ".gradle",
                    ".yml", ".yaml"}
        include_vendor = bool(r.params.get("include_vendor", False))
        hits = 0
        start = len(out)
        multiline = bool(r.params.get("multiline"))
        for dirpath, dirnames, files in os.walk(base):
            rel = os.path.relpath(dirpath, base)
            if not include_vendor and any(
                    rel == vp or rel.startswith(vp + os.sep)
                    for vp in VENDOR_PREFIXES):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d not in skip_dirs]
            if any(part in skip_dirs for part in rel.split(os.sep)):
                continue
            for fn in files:
                if os.path.splitext(fn)[1].lower() not in exts:
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        if multiline:
                            content = fh.read(500_000)
                            m = rx.search(content)
                            if m:
                                rel = os.path.relpath(p, decoded)
                                out.append(R.finding(
                                    r, file=rel,
                                    evidence=f"{rel}: {m.group(0)[:200]}",
                                    extra={"multiline": True}))
                                hits += 1
                        else:
                            for ln, line in enumerate(fh, 1):
                                if rx.search(line):
                                    rel = os.path.relpath(p, decoded)
                                    out.append(R.finding(
                                        r, file=rel,
                                        evidence=f"{rel}:{ln}: {line.strip()[:200]}",
                                        extra={"line": ln}))
                                    hits += 1
                                    if hits >= limit:
                                        break
                                elif (ent_min and len(line) < 20_000
                                        and _ENT_HINT_RE.search(line)
                                        and os.path.splitext(fn)[1].lower() in ent_exts):
                                    for tok in _TOKEN_RE.findall(line):
                                        if len(tok) >= 20:
                                            h = _shannon(tok)
                                            if h >= ent_min:
                                                rel = os.path.relpath(p, decoded)
                                                out.append(R.finding(
                                                    r, file=rel,
                                                    evidence=(f"{rel}:{ln}: high-entropy token "
                                                              f"{tok[:24]}… (H={h:.1f})"),
                                                    extra={"line": ln, "entropy": round(h, 2)}))
                                                hits += 1
                                                break
                                    if hits >= limit:
                                        break
                                if hits >= limit:
                                    break
                except OSError:
                    continue
                if hits >= limit:
                    break
            if hits >= limit:
                break
        if hits >= limit:
            # Silent truncation is a lie: mark every finding from this rule and
            # leave a human-visible note on the last one.
            for i in range(start, len(out)):
                det = out[i].setdefault("detail", {})
                det["truncated"] = True
                det["limit"] = limit
            out[-1]["evidence"] += f" [truncated at {limit} hits]"
    return out


# ------------------------------------------------------------------- analyse
def analyse(apk: str, out_root: str, *, rules_dir: str = DEFAULT_RULES,
            do_decode: bool = True, do_regex: bool = True,
            preflight_check: bool = True, platform_perms: str | None = None) -> dict:
    digest = sha256(apk)
    ws = workspace(out_root, digest)
    decode_dir = os.path.join(ws, "apktool")

    pre = apktools.preflight(apk) if preflight_check else {"ok": True, "issues": []}
    decoded_ok, decode_msg = (False, "decode skipped")
    man: dict = {}
    nsc: list[dict] = []

    blind_code = False
    if do_decode and pre.get("ok", True):
        decoded_ok, decode_msg = apktools.decode(apk, decode_dir)
        if decoded_ok:
            man = mf.parse(os.path.join(decode_dir, "AndroidManifest.xml"))
            nsc = mf.read_network_security_config(decode_dir)
        else:
            # Fallback: the manifest is the highest-value input and does not
            # need a JVM. Decode it directly so a missing/failing apktool
            # degrades instead of blinding the whole tool.
            fallback_ok, fb_msg = apktools.decode_manifest_only(apk, decode_dir)
            if fallback_ok:
                decoded_ok = True
                blind_code = True
                decode_msg = f"{decode_msg} | fallback: {fb_msg}"
                man = mf.parse(os.path.join(decode_dir, "AndroidManifest.xml"))
                # apktool also gives us res/xml bodies; without it we recover
                # them by content-scanning the APK for <network-security-config>.
                nsc = mf.find_network_security_config(apk)
    elif not pre.get("ok", True):
        decode_msg = "skipped: preflight blocked unpack"

    st = apktools.structure(apk)
    sig = apktools.signature(apk)
    bad = apktools.badging(apk)
    pk = apktools.packer(apk)
    packed = apktools.packed_verdict(pk, st)

    # aapt2 can supply identity when the manifest could not be decoded
    package = man.get("package") or bad.get("package", "")
    version_name = man.get("version_name") or bad.get("versionName", "")
    version_code = man.get("version_code") or bad.get("versionCode", "")
    min_sdk = man.get("min_sdk") or bad.get("minSdk", "")
    target_sdk = man.get("target_sdk") or bad.get("targetSdk", "")
    perms = man.get("uses_permissions") or bad.get("permissions", [])

    all_rules, rule_errors = R.load_dir(rules_dir)
    ppath = platform_perms or os.path.join(rules_dir, "platform_permissions.txt")
    platform = load_platform_perms(ppath)
    if not platform:
        rule_errors.append(f"platform permission list empty or missing: {ppath} "
                           f"(AS-0002 will over-report)")

    # Blob-level findings that are not rule driven (kept always-on, high signal)
    findings: list[dict] = []
    if packed:
        for p in packed:
            findings.append({
                "id": "BLIND-0001", "tool": "apk-surface", "rule": "BLIND-0001",
                "title": "Packed/protected sample - code-level analysis is unreliable",
                "severity": "info", "kind": "integrity", "component": "", "file": "",
                "evidence": f"packer indicators: {', '.join(packed)}",
                "recommendation": ("Unpack from memory before drawing conclusions. Every code-level "
                                   "rule below found nothing because it is blind, not because the "
                                   "app is clean."),
                "maswe": None, "static_only": True,
                "verification": {"status": "n/a", "script": None},
            })

    if decoded_ok and man:
        file_paths = mf.read_file_provider_paths(decode_dir) if (
            decoded_ok and not blind_code) else []
        backup_rules = mf.read_backup_rules(decode_dir, man) if (
            decoded_ok and not blind_code) else []
        findings += check_manifest(all_rules, man, nsc, platform, file_paths,
                                   sig, backup_rules)
        if blind_code:
            findings.append({
                "id": "BLIND-0003", "tool": "apk-surface", "rule": "BLIND-0003",
                "title": "Manifest-only decode - no code was analysed",
                "severity": "info", "kind": "integrity", "component": "", "file": "",
                "evidence": decode_msg,
                "recommendation": ("apktool was unavailable or failed, so the manifest was read with "
                                   "the built-in AXML parser. Every code-level rule is blind here. "
                                   "Install apktool and re-run for full coverage."),
                "maswe": None, "static_only": True,
                "verification": {"status": "n/a", "script": None},
            })
        if do_regex and not packed and not blind_code:
            from . import taint_smali as TS  # local: taint_smali imports VENDOR_PREFIXES from here
            findings += check_regex([r for r in all_rules if r.kind == "regex"],
                                    decode_dir)
            findings += TS.scan(decode_dir, [r for r in all_rules if r.kind == "smali-taint"])
            by_id = {r.id: r for r in all_rules}
            if st.get("so_files"):
                findings += check_native(by_id, apk)
        elif do_regex and (packed or blind_code):
            findings.append({
                "id": "BLIND-0002", "tool": "apk-surface", "rule": "BLIND-0002",
                "title": "Regex rules skipped (sample is packed)",
                "severity": "info", "kind": "integrity", "component": "", "file": "",
                "evidence": f"{len([r for r in all_rules if r.kind in ('regex', 'smali-taint')])} code rules not run "
                            f"({'packed' if packed else 'manifest-only decode'})",
                "recommendation": "Unpack first, then re-run.",
                "maswe": None, "static_only": True,
                "verification": {"status": "n/a", "script": None},
            })

    findings = R.sort_findings(findings)
    sev_count: dict[str, int] = {}
    for f in findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    report = {
        "tool": "apk-surface",
        "version": "0.2.0",
        "generated_at": now(),
        "apk_path": os.path.abspath(apk),
        "apk_sha256": digest,
        "size": os.path.getsize(apk),
        "workspace": ws,
        "package": package,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "flags": man.get("application", {}),
        "uses_permissions": perms,
        "defined_permissions": man.get("defined_permissions", []),
        "components": man.get("components", []),
        "deeplinks": man.get("deeplinks", []),
        "app_links": man.get("app_links", []),
        "custom_schemes": man.get("custom_schemes", []),
        "meta_data": man.get("meta_data", []),
        "file_provider_paths": file_paths if decoded_ok and man else [],
        "backup_rules": backup_rules if decoded_ok and man else [],
        "network_security_config": nsc,
        "signature": sig,
        "structure": st,
        "packer_hints": packed,
        "preflight": pre,
        "decode": {"ok": decoded_ok, "detail": decode_msg, "manifest_only": blind_code,
                   "dir": decode_dir if decoded_ok else None},
        "platform_permissions_known": len(platform),
        "rule_errors": rule_errors,
        "rule_count": len(all_rules),
        "findings": findings,
        "severity_counts": sev_count,
    }
    write_json(os.path.join(ws, "analysis.json"), report)
    if findings:
        from .utils import append_jsonl
        append_jsonl(os.path.join(out_root, "findings.jsonl"), {
            "sample": digest[:12], "package": package, "version_name": version_name,
            "ts": report["generated_at"],
            "severity_counts": sev_count,
            "findings": findings,
        })
    return report
