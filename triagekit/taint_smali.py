"""Intra-method smali register taint: Intent sources -> dangerous sinks."""
from __future__ import annotations

import os
import re

from . import rules as R
from .analyzer import VENDOR_PREFIXES

_DEFAULT_SOURCES = ("getIntent", "getData", "getStringExtra",
                    "getParcelableExtra", "getSerializableExtra")
_DEFAULT_SINKS = ("loadUrl", "addJavascriptInterface", "startActivity",
                  "startService", "sendBroadcast", "setClass")

_MOVE_RE = re.compile(
    r"^\s*move(?:-result|-object|-wide|-result-object)?(?:/from16|/16)?\s+"
    r"(v\d+|p\d+)", re.I)
_MOVE_RESULT_RE = re.compile(
    r"^\s*move-result(?:-object|-wide)?(?:/from16|/16)?\s+(v\d+|p\d+)",
    re.I)
_KILL_RE = re.compile(
    r"^\s*(?:const(?:-string(?:/jumbo)?|-class|-method-handle|-method-type)?|"
    r"new-instance|new-array|aget(?:-wide|-object|-boolean|-byte|-char|-short)?|"
    r"fill-array-data)"
    r"(?:/from16|/16|/jumbo)?\s+(v\d+|p\d+)", re.I)
_METHOD_RE = re.compile(r"^\s*\.method\b(.*)$", re.I)
_END_METHOD_RE = re.compile(r"^\s*\.end\s+method", re.I)
_INVOKE_RE = re.compile(r"^\s*invoke-\S+\s*\{([^}]*)\},\s*(\S+)->(\S+)\(", re.I)


def _regs(arglist: str) -> list[str]:
    """Split an invoke register list, expanding `{v0 .. v3}` ranges."""
    out: list[str] = []
    arglist = arglist.strip()
    if ".." in arglist:
        parts = [a.strip() for a in re.split(r"\.\.", arglist)]
        if len(parts) == 2:
            m1 = re.match(r"([vp])(\d+)", parts[0].lstrip("{ "))
            m2 = re.match(r"([vp])(\d+)", parts[1].rstrip("} "))
            if m1 and m2 and m1.group(1) == m2.group(1):
                return [f"{m1.group(1)}{i}"
                        for i in range(int(m1.group(2)), int(m2.group(2)) + 1)]
    return [a.strip() for a in arglist.split(",")
            if a.strip().startswith(("v", "p"))]


def _scan_method(lines: list[str], src_pat: re.Pattern, sink_pat: re.Pattern) -> list[dict]:
    """Return [{src_line, sink_line, sink, reg, path}] for one .method body."""
    tainted: dict[str, dict] = {}
    pending_src: dict | None = None
    hits: list[dict] = []
    for i, line in enumerate(lines):
        m = _INVOKE_RE.match(line)
        if m:
            args, owner, method = m.groups()
            regs = _regs(args)
            if src_pat.search(method) or src_pat.search(owner):
                pending_src = {"line": i, "method": method.strip()}
                continue
            # A non-source call breaks the source→move-result chain and its
            # result register is a fresh (untainted) value.
            pending_src = None
            if sink_pat.search(method):
                for reg in regs:
                    if reg in tainted:
                        t = tainted[reg]
                        hits.append({"src_line": t["line"],
                                     "src_method": t["method"],
                                     "sink_line": i, "sink": method.strip(),
                                     "reg": reg,
                                     "path": t.get("path", []) + [reg]})
                        break
            continue
        m = _MOVE_RESULT_RE.match(line)
        if m:
            reg = m.group(1)
            if pending_src is not None:
                tainted[reg] = {"line": pending_src["line"],
                                "method": pending_src["method"],
                                "path": [reg]}
                pending_src = None
            else:
                tainted.pop(reg, None)  # fresh value kills old taint
            continue
        m = _KILL_RE.match(line)
        if m:
            tainted.pop(m.group(1), None)
            continue
        m = _MOVE_RE.match(line)
        if m:
            parts = re.split(r"[,\s]+", line.strip())
            dst = parts[1].rstrip(",;") if len(parts) > 1 else ""
            srcs = [p.rstrip(",;") for p in parts[2:]]
            hit = [s for s in srcs if s in tainted]
            if dst and hit:
                tainted[dst] = {"line": tainted[hit[0]]["line"],
                                "method": tainted[hit[0]]["method"],
                                "path": tainted[hit[0]].get("path", []) + [dst]}
    return hits


def scan(decoded: str, rules: list, limit_default: int = 15) -> list[dict]:
    out: list[dict] = []
    if not decoded or not os.path.isdir(decoded):
        return out
    for r in rules:
        sources = r.params.get("sources", list(_DEFAULT_SOURCES))
        sinks = r.params.get("sinks", list(_DEFAULT_SINKS))
        try:
            cap = int(r.params.get("cap", limit_default))
        except (TypeError, ValueError):
            cap = limit_default
        if cap <= 0:
            cap = limit_default
        include_vendor = bool(r.params.get("include_vendor", False))
        skip_dirs = set(r.params.get("skip_dirs", []))
        try:
            src_pat = re.compile(r"\b(?:" + "|".join(sources) + r")\b")
            sink_pat = re.compile(r"\b(?:" + "|".join(sinks) + r")\b")
        except re.error as e:
            out.append(R.finding(r, evidence=f"bad taint pattern: {e}"))
            continue
        base = os.path.join(decoded, r.params.get("root", "."))
        if not os.path.isdir(base):
            continue
        hits = 0
        start = len(out)
        for dirpath, dirnames, files in os.walk(base):
            rel = os.path.relpath(dirpath, base)
            if not include_vendor and any(
                    rel == vp or rel.startswith(vp + os.sep)
                    for vp in VENDOR_PREFIXES):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d not in skip_dirs]
            if any(part in skip_dirs for part in
                   os.path.relpath(dirpath, base).split(os.sep)):
                continue
            for fn in files:
                if not fn.endswith(".smali"):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        content = fh.read(500_000)
                except OSError:
                    continue
                block: list[str] = []
                in_method = False
                sig = ""
                base_ln = 0

                def emit() -> bool:
                    """Scan the current block; True when the cap is hit."""
                    nonlocal hits
                    for h in _scan_method(block, src_pat, sink_pat):
                        relp = os.path.relpath(p, decoded)
                        out.append(R.finding(
                            r, file=relp,
                            evidence=(f"{relp}:{sig}: tainted {h['reg']} "
                                      f"from {h['src_method']} reaches "
                                      f"{h['sink']}"),
                            extra={"method": sig, "sink": h["sink"],
                                   "reg": h["reg"],
                                   "src_method": h["src_method"],
                                   "src_line": base_ln + h["src_line"],
                                   "sink_line": base_ln + h["sink_line"]}))
                        hits += 1
                        if hits >= cap:
                            return True
                    return False

                for ln, raw in enumerate(content.splitlines()):
                    if _METHOD_RE.match(raw):
                        in_method = True
                        block = [raw]
                        sig = raw.strip()[:120]
                        base_ln = ln
                        continue
                    if in_method:
                        block.append(raw)
                    if in_method and _END_METHOD_RE.match(raw):
                        in_method = False
                        if emit():
                            break
                    if hits >= cap:
                        break
                if in_method:
                    # Truncated file: scan the unterminated tail rather than
                    # dropping it (never raises, may under-report).
                    emit()
                if hits >= cap:
                    break
            if hits >= cap:
                break
        if hits >= cap:
            for i in range(start, len(out)):
                det = out[i].setdefault("detail", {})
                det["truncated"] = True
                det["limit"] = cap
            out[-1]["evidence"] += f" [truncated at {cap} hits]"
    return out
