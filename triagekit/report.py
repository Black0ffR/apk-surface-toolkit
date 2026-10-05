"""Markdown report renderer."""
from __future__ import annotations

import os

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _b(v) -> str:
    return "yes" if v is True else ("no" if v is False else (str(v) if v not in (None, "") else "—"))


def _tbl(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in r) + " |")
    return "\n".join(out) + "\n"


def render(r: dict) -> str:
    L: list[str] = []
    L.append(f"# APK surface report — `{r.get('package') or 'unknown'}`")
    L.append("")
    L.append(f"**{r.get('version_name') or '?'}** (versionCode {r.get('version_code') or '?'}) · "
             f"minSdk {r.get('min_sdk') or '?'} · targetSdk {r.get('target_sdk') or '?'}")
    L.append("")
    L.append(f"- APK: `{os.path.basename(r.get('apk_path',''))}`")
    L.append(f"- SHA-256: `{r.get('apk_sha256','')}`")
    L.append(f"- Size: {r.get('size', 0) / 1_048_576:.1f} MB · "
             f"{r.get('structure', {}).get('entries', 0)} zip entries")
    L.append(f"- Generated: {r.get('generated_at')}")
    L.append("")

    # ---- verdict
    counts = r.get("severity_counts", {})
    total = sum(counts.values())
    L.append("## Verdict")
    L.append("")
    if r.get("packer_hints"):
        L.append(f"> ⚠️ **Packed sample** ({', '.join(r['packer_hints'])}). Manifest findings below are "
                 f"valid; every code-level rule is blind. Unpack before trusting a clean result.")
        L.append("")
    if not r.get("decode", {}).get("ok"):
        L.append(f"> ⚠️ **apktool decode did not run**: {r.get('decode', {}).get('detail')}")
        L.append("")
    L.append(f"**{total} finding(s)**: " + " · ".join(
        f"{SEV_ICON[s]} {counts[s]} {s}" for s in SEV_ORDER if counts.get(s)) or "0 findings")
    L.append("")

    # ---- signature
    s = r.get("signature", {})
    L.append("## Identity & signature")
    L.append("")
    if s.get("ok"):
        schemes = " ".join(k.upper() for k in ("v1", "v2", "v3", "v4") if s.get(k))
        L.append(f"- Signer SHA-256: `{s.get('sha256','?')}`")
        L.append(f"- DN: `{s.get('dn','?')}`")
        L.append(f"- Schemes: {schemes or 'unknown'}")
    else:
        L.append(f"- ⚠️ could not verify: {s.get('note')}")
    L.append("")

    # ---- structure
    st = r.get("structure", {})
    L.append("## Structure")
    L.append("")
    L.append(_tbl(["Property", "Value"], [
        ["DEX files", f"{len(st.get('dex', []))} ({st.get('dex_bytes', 0) // 1024} KB)"],
        ["Native libs", f"{len(st.get('so_files', []))} across {', '.join(st.get('abis', [])) or 'n/a'}"],
        ["Assets", f"{st.get('assets_bytes', 0) // 1024} KB"],
        ["Res files", st.get("res_files", 0)],
    ]))
    if st.get("so_files"):
        L.append("\n<details><summary>native libraries</summary>\n")
        for n in st["so_files"][:40]:
            L.append(f"- `{n}`")
        L.append("\n</details>\n")

    # ---- flags
    flags = r.get("flags", {})
    L.append("## Security flags")
    L.append("")
    L.append(_tbl(["Flag", "Value"], [[f"`android:{k}`", _b(v)] for k, v in sorted(flags.items())])
             if flags else "_no application flags set_\n")

    # ---- network security config
    nsc = r.get("network_security_config", [])
    if nsc:
        L.append("## Network security config")
        L.append("")
        for cfg in nsc:
            L.append(f"**{cfg.get('file')}**")
            L.append("")
            L.append(_tbl(["Section", "cleartext", "trust anchors", "pins"],
                          [[d.get("kind"), _b(d.get("cleartext")), ", ".join(d.get("trust_anchors") or []) or "—",
                            ("yes" if d.get("pinning") else ("yes" if cfg.get("pins") else "no"))]
                           for d in cfg.get("domains", [])]))
            L.append("")

    # ---- permissions
    L.append("## Permissions")
    L.append("")
    used = r.get("uses_permissions", [])
    defined = r.get("defined_permissions", [])
    if used:
        L.append("```\n" + "\n".join(used) + "\n```")
    else:
        L.append("_none_")
    L.append("")
    if defined:
        L.append("Custom permissions declared by this app:")
        L.append("")
        L.append(_tbl(["Permission", "protectionLevel"],
                      [[f"`{p['name']}`", p.get("protection_level") or "normal (default)"] for p in defined]))
        L.append("")

    # ---- components
    L.append("## Components")
    L.append("")
    comps = r.get("components", [])
    rows = []
    for c in comps:
        rows.append([
            c["type"],
            f"`{c['name']}`",
            _b(c.get("exported")) + (" (implicit)" if c.get("exported_implicit") else ""),
            f"`{c.get('permission')}`" if c.get("permission") else "—",
            c.get("authorities") or "—",
        ])
    L.append(_tbl(["Type", "Name", "Exported", "Permission", "Authority"], rows))
    exported = [c for c in comps if c.get("exported")]
    L.append(f"\n{len(exported)} of {len(comps)} components are exported.\n")

    # ---- deep links
    L.append("## Deep links")
    L.append("")
    if r.get("app_links"):
        L.append("**App Links (http/https)**")
        L.append("")
        L.append(_tbl(["Scheme", "Host", "autoVerify", "Component"],
                      [[a["scheme"], a.get("host") or "—", _b(a.get("auto_verify")),
                        f"`{a['component']}`"] for a in r["app_links"]]))
    if r.get("custom_schemes"):
        L.append("**Custom schemes**")
        L.append("")
        L.append(_tbl(["Scheme", "Host", "Component"],
                      [[c["scheme"], c.get("host") or "—", f"`{c['component']}`"]
                       for c in r["custom_schemes"]]))
    if not (r.get("app_links") or r.get("custom_schemes")):
        L.append("_none_")
    L.append("")

    # ---- findings
    L.append("## Findings")
    L.append("")
    f = r.get("findings", [])
    if not f:
        L.append("_No findings matched the loaded rule set. That is not the same as "
                 "'the app is secure' — check whether the sample was packed and which rules ran._")
        L.append("")
    for sev in SEV_ORDER:
        group = [x for x in f if x.get("severity") == sev]
        if not group:
            continue
        L.append(f"### {SEV_ICON[sev]} {sev.title()} ({len(group)})")
        L.append("")
        for x in group:
            L.append(f"**`{x.get('rule')}` {x.get('title')}**")
            L.append("")
            if x.get("maswe"):
                L.append(f"- OWASP: `{x['maswe']}`")
            if x.get("component"):
                L.append(f"- Component: `{x['component']}`")
            if x.get("file"):
                L.append(f"- File: `{x['file']}`")
            if x.get("evidence"):
                L.append(f"- Evidence: {x['evidence']}")
            if x.get("recommendation"):
                L.append(f"- Fix: {x['recommendation']}")
            if x.get("repro"):
                L.append(f"- Manual test: `{x['repro']}`")
            L.append(f"- Verification: **{x.get('verification', {}).get('status', 'unverified')}**")
            L.append("")

    if r.get("rule_errors"):
        L.append("## Rule load errors")
        L.append("")
        for e in r["rule_errors"]:
            L.append(f"- `{e}`")
        L.append("")

    L.append("---")
    L.append("")
    L.append("_Static analysis only. Every finding is a hypothesis until reproduced at runtime. "
             "Use the generated `tests.sh` for that — review each command before running it._")
    L.append("")
    return "\n".join(L)


def write(r: dict, path: str) -> str:
    md = render(r)
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    return path
