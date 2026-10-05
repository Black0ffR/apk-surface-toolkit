"""apk-surface / triage CLI."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from . import __version__, apktools, diff as D, report as RPT, rules as R, tests_gen
from .analyzer import DEFAULT_RULES, analyse
from .utils import read_json, write_json

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _tri(v) -> str:
    """Render a possibly-absent tri-state flag honestly."""
    return "yes" if v is True else ("no" if v is False else "—")


# --------------------------------------------------------------------- human
def human(r: dict) -> str:
    L = []
    ident = f"{r.get('package') or '?'} {r.get('version_name') or ''}".strip()
    meta = f" minSdk {r.get('min_sdk') or '?'} · targetSdk {r.get('target_sdk') or '?'}"
    L.append(f"[+] {ident}{meta}")
    s = r.get("signature", {})
    if s.get("ok"):
        schemes = " ".join(k.upper() for k in ("v1", "v2", "v3", "v4") if s.get(k))
        L.append(f"[+] signer {(s.get('sha256') or '?')[:32]}… · {schemes or 'scheme unknown'}")
    else:
        L.append(f"[!] signature: {s.get('note')}")
    st = r.get("structure", {})
    L.append(f"[+] {len(st.get('dex', []))} dex ({st.get('dex_bytes', 0) // 1024} KB) · "
             f"{len(st.get('so_files', []))} native · {st.get('entries', 0)} entries")
    comps = r.get("components", [])
    exp = [c for c in comps if c.get("exported")]
    L.append(f"[+] {len(comps)} components · {len(exp)} exported · "
             f"{len(r.get('deeplinks', []))} deep links · {len(r.get('custom_schemes', []))} custom schemes")
    if r.get("packer_hints"):
        L.append(f"[!] PACKED ({', '.join(r['packer_hints'])}) — code-level rules are blind")
    counts = r.get("severity_counts", {})
    total = sum(counts.values())
    L.append(("[+] no findings matched the rule set" if total == 0 else
              "[!] " + "  ".join(f"{SEV_ICON[k]}{counts[k]}" for k in
                                 ("critical", "high", "medium", "low", "info") if counts.get(k))))
    for f in r.get("findings", []):
        if f.get("severity") in ("critical", "high", "medium"):
            L.append(f"    {SEV_ICON[f['severity']]} {f['rule']} {f['title']}"
                     + (f"  [{f['component']}]" if f.get("component") else ""))

    # Blind-spot warnings. Silence must never be mistakable for a clean result.
    if not r.get("decode", {}).get("ok"):
        L.append("")
        L.append(f"[!!] MANIFEST NOT ANALYSED — {r['decode'].get('detail')}")
        L.append("[!!] The 0 findings above mean 'I could not look', not 'nothing is wrong'.")
    elif r.get("decode", {}).get("manifest_only"):
        L.append("")
        L.append("[i] manifest-only decode (apktool unavailable/failed) — built-in AXML parser was used")
        L.append("[i] manifest findings are VALID; code-level rules did not run (no smali to read)")
    if r.get("preflight", {}).get("issues"):
        for i in r["preflight"]["issues"]:
            L.append(f"[!!] preflight: {i}")
    if r.get("rule_errors"):
        for e in r["rule_errors"]:
            L.append(f"[!!] rule load error: {e}")

    L.append(f"==> workspace: {r.get('workspace')}")
    L.append("==> report.md · tests.sh · analysis.json")
    return "\n".join(L)


def route(r: dict) -> tuple[str, str]:
    """The routing decision: what should the analyst do next."""
    if not r.get("decode", {}).get("ok"):
        return ("decode", "apktool decode failed — check the framework jar and the packer verdict")
    if r.get("packer_hints"):
        return ("unpack", "packed sample: dump dex from memory, then re-analyse the dump")
    if any(f.get("severity") in ("critical", "high") for f in r.get("findings", [])):
        return ("verify", "read tests.sh, review each command, then run it with --execute")
    if r.get("deeplinks") or r.get("custom_schemes"):
        return ("deeplink", "test every deep link with `am start -a VIEW -d <uri>`")
    if any(f.get("severity") == "medium" for f in r.get("findings", [])):
        return ("verify", "medium findings: confirm at runtime before reporting")
    return ("complete", "no actionable surface found — add rules or move to the next sample")


# ------------------------------------------------------------------ commands
def cmd_analyze(a) -> int:
    apks = []
    if os.path.isdir(a.target):
        for root, _, files in os.walk(a.target):
            apks += [os.path.join(root, f) for f in files if f.endswith((".apk", ".apkm", ".xapk"))]
    else:
        apks = [a.target]
    if not apks:
        print("no apk found", file=sys.stderr)
        return 2

    rc = 0
    results = []
    for apk in apks:
        if a.preflight_only:
            pre = apktools.preflight(apk)
            print(f"[{'ok' if pre['ok'] else '!!'}] {apk}: {pre['entry_count']} entries, "
                  f"max ratio {pre['max_ratio']:.0f}")
            for i in pre["issues"]:
                print(f"     !! {i}")
            continue
        r = analyse(apk, a.out, rules_dir=a.rules, do_decode=not a.no_decode,
                    do_regex=not a.no_regex, preflight_check=True,
                    platform_perms=a.platform_perms)
        results.append(r)
        ws = r["workspace"]
        RPT.write(r, os.path.join(ws, "report.md"))
        tpath = tests_gen.generate(r, os.path.join(ws, "tests.sh"))
        if a.json:
            print(json.dumps(r, indent=2, ensure_ascii=False))
        elif a.quiet:
            print(f"{os.path.basename(apk)} -> {ws}")
        else:
            print(human(r))
            kind, why = route(r)
            print(f"==> next ({kind}): {why}")
            print()
        if a.execute:
            print(f"### executing {tpath} — review the file first if you have not already")
            if a.yes or input("type 'run' to execute: ").strip() == "run":
                subprocess.run(["bash", tpath])
            else:
                print("skipped.")
        if any(f.get("severity") in ("critical", "high") for f in r.get("findings", [])):
            rc = 1
        if not r.get("decode", {}).get("ok"):
            rc = 3   # INCOMPLETE: distinct from CLEAN(0) and FINDINGS(1)
    if a.jsonl:
        for r in results:
            from .utils import append_jsonl
            append_jsonl(os.path.join(a.out, "findings.jsonl"),
                         {"sample": r["apk_sha256"][:12], "package": r["package"],
                          "version_name": r["version_name"], "ts": r["generated_at"],
                          "severity_counts": r["severity_counts"],
                          "findings": [{"rule": f["rule"], "severity": f["severity"],
                                        "title": f["title"], "component": f.get("component", "")}
                                       for f in r["findings"]]})
    return rc


def cmd_query(a) -> int:
    r = read_json(os.path.join(a.analysis, "analysis.json"))
    rows = []
    if a.type == "deeplink":
        # deeplinks[] is canonical: one entry per <data> element. custom_schemes
        # and app_links are the same objects split by scheme, so concatenating
        # them here would report every link two or three times.
        for d in r.get("deeplinks", []):
            rows.append([d.get("component", ""), d.get("scheme", ""), d.get("host") or "",
                         _tri(d.get("auto_verify"))])
        hdr = ["component", "scheme", "host", "autoVerify"]
    else:
        for c in r.get("components", []):
            if c["type"] != a.type:
                continue
            if a.exported and not c.get("exported"):
                continue
            rows.append([c["type"], c["name"], _tri(c.get("exported")),
                         c.get("permission") or "", c.get("authorities") or ""])
        hdr = ["type", "name", "exported", "permission", "authorities"]
    if a.csv:
        import csv
        w = csv.writer(sys.stdout)
        w.writerow(hdr)
        w.writerows(rows)
    else:
        print(" | ".join(hdr))
        for x in rows:
            print(" | ".join(str(v) for v in x))
    return 0


def cmd_diff(a) -> int:
    old = read_json(a.old)
    new = read_json(a.new)
    d = D.diff(old, new)
    if a.json:
        print(json.dumps(d, indent=2))
    else:
        print(D.render(d))
    return 0


def cmd_doctor(_a) -> int:
    d = apktools.doctor()
    print("apk-surface environment")
    for k, v in d.items():
        if k == "complete":
            continue
        print(f"  {k:<12}{'ok' if v else 'MISSING'}")
    if not d["complete"]:
        print("\n  install: pkg install apktool apksigner aapt2 && pip install apkid")
    return 0 if d["complete"] else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apk-surface",
        description="Static attack-surface mapping for Android APKs (a.k.a. triage v0.2)")
    p.add_argument("--version", action="version", version=f"apk-surface {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser("analyze", help="analyse one APK or a directory")
    an.add_argument("target")
    an.add_argument("-o", "--out", default=os.path.expanduser("~/re/projects"))
    an.add_argument("--rules", default=DEFAULT_RULES)
    an.add_argument("--platform-perms", default=None,
                    help="override rules/platform_permissions.txt (a snapshot, not a spec)")
    an.add_argument("--format", default="text", choices=["text", "json"])
    an.add_argument("--json", action="store_true")
    an.add_argument("--jsonl", action="store_true", help="append a summary to findings.jsonl")
    an.add_argument("--no-decode", action="store_true")
    an.add_argument("--no-regex", action="store_true")
    an.add_argument("--preflight", action="store_true", dest="preflight_only",
                    help="safety check only, do not unpack")
    an.add_argument("--quiet", action="store_true")
    an.add_argument("--execute", action="store_true",
                    help="RUN the generated tests.sh (default is emit-only)")
    an.add_argument("-y", "--yes", action="store_true", help="skip the --execute confirmation")
    an.set_defaults(func=cmd_analyze)

    q = sub.add_parser("query", help="query a previous analysis")
    q.add_argument("analysis", help="workspace dir containing analysis.json")
    q.add_argument("--type", default="activity",
                   choices=["activity", "activity-alias", "service", "receiver", "provider", "deeplink"])
    q.add_argument("--exported", action="store_true")
    q.add_argument("--csv", action="store_true")
    q.set_defaults(func=cmd_query)

    d = sub.add_parser("diff", help="diff two analysis.json files")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_diff)

    doc = sub.add_parser("doctor", help="check the environment")
    doc.set_defaults(func=cmd_doctor)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "analyze":
        a.json = a.json or a.format == "json"
    return a.func(a)
