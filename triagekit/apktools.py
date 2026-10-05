"""Wrappers around external binaries. All optional; all argv-list based."""
from __future__ import annotations

import json
import os
import re
import zipfile

from .utils import have, run, which


def badging(apk: str) -> dict:
    """aapt2/aapt dump badging -> package, versions, permissions, launchable."""
    exe = which("aapt2") or which("aapt")
    if not exe:
        return {}
    rc, out = run([exe, "dump", "badging", apk], timeout=90)
    if rc != 0:
        return {}
    d: dict = {"permissions": []}
    for line in out.splitlines():
        if line.startswith("package: name="):
            m = re.search(r"name='([^']+)'", line)
            d["package"] = m.group(1) if m else ""
            for key in ("versionCode", "versionName"):
                m = re.search(key + r"='([^']+)'", line)
                if m:
                    d[key] = m.group(1)
        elif line.startswith("sdkVersion:"):
            d["minSdk"] = re.search(r"'([^']+)'", line).group(1) if "'" in line else ""
        elif line.startswith("targetSdkVersion:"):
            d["targetSdk"] = re.search(r"'([^']+)'", line).group(1) if "'" in line else ""
        elif line.startswith("launchable-activity:"):
            m = re.search(r"name='([^']+)'", line)
            d["launchable"] = m.group(1) if m else ""
        elif line.startswith("uses-permission:"):
            m = re.search(r"name='([^']+)'", line)
            if m:
                d["permissions"].append(m.group(1))
    return d


def signature(apk: str) -> dict:
    if not which("apksigner"):
        return {"ok": False, "note": "apksigner not installed (pkg install apksigner)"}
    rc, out = run(["apksigner", "verify", "--verbose", "--print-certs", apk], timeout=120)
    d: dict = {"ok": rc == 0}
    m = re.search(r"Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]+)", out)
    if m:
        d["sha256"] = m.group(1)
    m = re.search(r"Signer #1 certificate DN: (.+)", out)
    if m:
        d["dn"] = m.group(1).strip()
    for scheme in ("v1", "v2", "v3", "v4"):
        m = re.search(scheme + r" scheme[^:]*: (true|false)", out, re.I)
        if m:
            d[scheme] = m.group(1) == "true"
    if not d["ok"]:
        d["note"] = (out.splitlines() or ["verification failed"])[0]
    return d


def structure(apk: str) -> dict:
    d: dict = {"dex": [], "dex_bytes": 0, "so_files": [], "assets_bytes": 0,
               "entries": 0, "abis": [], "res_files": 0, "error": None}
    try:
        with zipfile.ZipFile(apk) as z:
            abis = set()
            for i in z.infolist():
                d["entries"] += 1
                n = i.filename
                if re.fullmatch(r"classes\d*\.dex", n):
                    d["dex"].append(n)
                    d["dex_bytes"] += i.file_size
                elif n.startswith("lib/") and n.endswith(".so"):
                    d["so_files"].append(n)
                    m = n.split("/")
                    if len(m) > 1:
                        abis.add(m[1])
                elif n.startswith("assets/"):
                    d["assets_bytes"] += i.file_size
                elif n.startswith("res/"):
                    d["res_files"] += 1
            d["abis"] = sorted(abis)
    except zipfile.BadZipFile:
        d["error"] = "not a valid zip / not an apk"
    except Exception as e:  # noqa: BLE001
        d["error"] = str(e)
    return d


# ------------------------------------------------------------------- apktool
def decode(apk: str, out_dir: str, *, keep_res: bool = True, timeout: int = 600) -> tuple[bool, str]:
    """Full apktool decode. Optional: see decode_manifest_only for the fallback."""
    if not which("apktool"):
        return False, "apktool not installed (pkg install apktool)"
    if os.path.isdir(out_dir) and os.listdir(out_dir):
        # A fallback tree (manifest-only, no smali) must never masquerade as a
        # full decode: stale .manifest-only means wipe and re-decode fresh.
        if os.path.exists(os.path.join(out_dir, ".manifest-only")):
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)
        else:
            return True, f"reused existing decode: {out_dir}"
    os.makedirs(os.path.dirname(out_dir) or ".", exist_ok=True)
    cmd = ["apktool", "d", "-f"]
    if not keep_res:
        cmd.append("-s")
    cmd += [apk, "-o", out_dir]
    rc, out = run(cmd, timeout=timeout)
    if rc == 0:
        try:
            os.remove(os.path.join(out_dir, ".manifest-only"))
        except OSError:
            pass
    return (rc == 0), (out or "ok")


def decode_manifest_only(apk: str, out_dir: str) -> tuple[bool, str]:
    """Dependency-free manifest decode via the built-in AXML parser.

    Produces res/ and smali/ as EMPTY placeholders so the workspace shape stays
    consistent, and writes a decoded AndroidManifest.xml. Used when apktool is
    missing or fails, which is common on protected packages. The caller must
    treat a code-level rule pass over this tree as meaningless -- there is no
    code in it.
    """
    from . import axml
    try:
        raw = axml.extract_manifest_xml(apk)
        xml = axml.to_xml_string(axml.parse_bytes(raw))
    except Exception as e:  # noqa: BLE001
        return False, f"AXML parse failed: {type(e).__name__}: {e}"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "res"), exist_ok=True)
    with open(os.path.join(out_dir, "AndroidManifest.xml"), "w", encoding="utf-8") as f:
        f.write(xml)
    with open(os.path.join(out_dir, ".manifest-only"), "w", encoding="utf-8") as f:
        f.write("manifest-only fallback: no smali/res bodies (see decode_manifest_only)")
    return True, "manifest decoded with the built-in AXML parser (no smali/res bodies)"


def preflight(apk: str) -> dict:
    """Is it safe to unpack this? zip bomb, ZipSlip entries, archive nesting."""
    d = {"ok": True, "issues": [], "entry_count": 0, "max_ratio": 0.0}
    try:
        with zipfile.ZipFile(apk) as z:
            infos = z.infolist()
            d["entry_count"] = len(infos)
            total = sum(i.file_size for i in infos)
            for i in infos:
                n = i.filename
                if n.startswith("/") or ".." in n.replace("\\", "/").split("/"):
                    d["issues"].append(f"path traversal in entry: {n}")
                if i.compress_size > 0:
                    ratio = i.file_size / i.compress_size
                    d["max_ratio"] = max(d["max_ratio"], ratio)
                    if ratio > 200 and i.file_size > 10_000_000:
                        d["issues"].append(f"possible zip bomb: {n} ratio={ratio:.0f}")
            if total > 2_000_000_000:
                d["issues"].append(f"uncompressed total is {total/1e9:.1f} GB")
    except zipfile.BadZipFile:
        d["ok"] = False
        d["issues"].append("not a valid zip")
    except Exception as e:  # noqa: BLE001
        d["ok"] = False
        d["issues"].append(str(e))
    d["ok"] = d["ok"] and not d["issues"]
    return d


# ------------------------------------------------------------------ packers
PACKER_HINTS = (
    "jiagu", "bangcle", "ijiami", "360", "tencent", "ali", "baidu", "qihoo",
    "secneo", "legu", "secshell", "nagain", "appsealing", "secneo", "kasper",
)


def packer(apk: str) -> dict:
    if not which("apkid"):
        return {"ok": False, "note": "apkid not installed (pip install apkid)", "hints": []}
    rc, out = run(["apkid", "-j", apk], timeout=240)
    hints = []
    blob = out.lower()
    for h in PACKER_HINTS:
        if h in blob:
            hints.append(h)
    d = {"ok": rc == 0, "hints": sorted(set(hints))}
    try:
        d["raw"] = json.loads(out)
    except Exception:  # noqa: BLE001
        d["raw_text"] = out[:1500]
    return d


def packed_verdict(pk: dict, st: dict) -> list[str]:
    """Packers gate everything else: a packed sample makes code rules blind."""
    hits = list(pk.get("hints") or [])
    if st.get("dex_bytes", 0) and st["dex_bytes"] < 900_000:
        prot = [n for n in st.get("so_files", [])
                if re.search(r"(jiagu|shell|protect|sec|guard|legu)", n, re.I)]
        if prot:
            hits.append("tiny dex + protection library")
    return sorted(set(hits))


def doctor() -> dict:
    return {
        "apktool": bool(which("apktool")),
        "aapt2": bool(which("aapt2") or which("aapt")),
        "apksigner": bool(which("apksigner")),
        "apkid": bool(which("apkid")),
        "jadx": bool(which("jadx")),
        "r2": bool(which("r2")),
        "java": bool(which("java")),
        "complete": have("apktool", "apksigner"),
    }
