"""Smali-text call-graph index: refs-as-rows sqlite + recursive-CTE reachability.

Adapted from the smalisearch shape (methods/instructions tables, `reachable`
with an explicit truncated flag), but built from the apktool smali tree we
already decode — no DEX parser needed. stdlib only (sqlite3).
"""
from __future__ import annotations

import os
import re
import sqlite3

from .analyzer import VENDOR_PREFIXES

SCHEMA = """
CREATE TABLE methods (
    id   INTEGER PRIMARY KEY,
    sig  TEXT NOT NULL,
    cls  TEXT NOT NULL,
    name TEXT NOT NULL
);
CREATE INDEX methods_cls ON methods(cls);
CREATE TABLE instructions (
    method_id INTEGER NOT NULL REFERENCES methods(id),
    kind      TEXT NOT NULL,
    target    TEXT NOT NULL
);
CREATE INDEX instr_target ON instructions(target);
CREATE INDEX instr_method ON instructions(method_id);
"""

_CLASS_RE = re.compile(r"^\s*\.class\b.*?(L\S+?;)\s*$")
_METHOD_RE = re.compile(r"^\s*\.method\b(.*)$")
_END_METHOD_RE = re.compile(r"^\s*\.end\s+method")
_INVOKE_RE = re.compile(r"^\s*invoke-\S+\s*\{[^}]*\},\s*(\S+?)->(\S+?)\(")
_CONST_STR_RE = re.compile(r'^\s*const-string(?:/jumbo)?\s+\S+,\s*"(.*)"\s*$')
_FIELD_RE = re.compile(
    r"^\s*(iget|sget|iput|sput)(?:-wide|-object|-boolean|-byte|-char|-short)?\s+"
    r"\S+,\s*(\S+?)->(\S+?):")


def _sig(cls: str, name: str) -> str:
    name = name.split("(")[0]
    return f"{cls}->{name}" if "->" not in name else name


def build(decoded: str, *, include_vendor: bool = False) -> sqlite3.Connection:
    """Index a decoded smali tree. Returns an open :memory: connection."""
    con = sqlite3.connect(":memory:")
    con.executescript(SCHEMA)
    mid = 0
    mrows, irows = [], []
    for dirpath, dirnames, files in os.walk(decoded):
        rel = os.path.relpath(dirpath, decoded)
        if not include_vendor and any(
                rel == vp or rel.startswith(vp + os.sep)
                for vp in VENDOR_PREFIXES):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in files:
            if not fn.endswith(".smali"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    content = fh.read(500_000)
            except OSError:
                continue
            cls, in_method, meth, meth_id = "", False, "", 0
            for raw in content.splitlines():
                m = _CLASS_RE.match(raw)
                if m:
                    cls = m.group(1)
                    continue
                m = _METHOD_RE.match(raw)
                if m:
                    in_method = True
                    meth = m.group(1).strip().split()[-1]
                    mid += 1
                    meth_id = mid
                    mrows.append((mid, _sig(cls, meth), cls, meth))
                    continue
                if _END_METHOD_RE.match(raw):
                    in_method = False
                    continue
                if not in_method or not cls:
                    continue
                m = _INVOKE_RE.match(raw)
                if m:
                    irows.append((meth_id, "call",
                                  _sig(m.group(1), m.group(2))))
                    continue
                m = _CONST_STR_RE.match(raw)
                if m:
                    irows.append((meth_id, "string", m.group(1)))
                    continue
                m = _FIELD_RE.match(raw)
                if m:
                    kind = ("field-read" if m.group(1).startswith(("iget", "sget"))
                            else "field-write")
                    irows.append((meth_id, kind,
                                  _sig(m.group(2), m.group(3))))
    con.executemany("INSERT INTO methods VALUES (?,?,?,?)", mrows)
    con.executemany("INSERT INTO instructions VALUES (?,?,?)", irows)
    con.commit()
    return con


def reachable(con: sqlite3.Connection, seeds: list[str],
              limit: int = 5000) -> dict:
    """Transitive closure from seed sigs (UNION dedup terminates cycles)."""
    con.execute("DROP TABLE IF EXISTS _seed")
    con.execute("CREATE TEMP TABLE _seed (sig TEXT PRIMARY KEY)")
    con.executemany("INSERT OR IGNORE INTO _seed VALUES (?)",
                    [(s,) for s in seeds])
    rows = con.execute(
        """
        WITH RECURSIVE
        reach(sig) AS (
            SELECT sig FROM _seed
            UNION
            SELECT i.target
            FROM reach r
            JOIN methods m ON m.sig = r.sig
            JOIN instructions i ON i.method_id = m.id
            WHERE i.kind = 'call'
        )
        SELECT sig FROM reach LIMIT ?
        """, (limit + 1,)).fetchall()
    return {"rows": [{"sig": s} for (s,) in rows[:limit]],
            "truncated": len(rows) > limit, "limit": limit}


def callers_of(con: sqlite3.Connection, target: str) -> list[dict]:
    """Every method containing a call to target (substring match)."""
    return [{"caller": sig}
            for (sig,) in con.execute(
                "SELECT DISTINCT m.sig FROM instructions i "
                "JOIN methods m ON m.id = i.method_id "
                "WHERE i.kind = 'call' AND i.target LIKE ? "
                "ORDER BY m.sig", (f"%{target}%",))]


_DEFAULT_SINKS = ("loadUrl", "addJavascriptInterface", "Runtime;->exec",
                  "DexClassLoader", "PathClassLoader")


def check_reachability(rules: list, decoded: str, man: dict,
                       limit: int = 15) -> list[dict]:
    """Exported entry points that can reach sensitive sinks (high)."""
    from . import rules as R
    if not decoded or not os.path.isdir(decoded):
        return []
    out: list[dict] = []
    comps = [c for c in man.get("components", []) if c.get("exported")]
    if not comps:
        return out
    con = build(decoded)
    try:
        for r in rules:
            sinks = r.params.get("sinks", list(_DEFAULT_SINKS))
            cap = int(r.params.get("cap", limit))
            hits = 0
            start = len(out)
            for comp in comps:
                cls = "L" + comp["name"].replace(".", "/")
                seeds = [s for (s,) in con.execute(
                    "SELECT sig FROM methods WHERE cls = ? OR cls LIKE ?",
                    (cls + ";", cls + "$%;")).fetchall()]
                if not seeds:
                    continue
                rset = {x["sig"] for x in
                        reachable(con, seeds)["rows"]}
                for sink in sinks:
                    callers = {x["caller"] for x in callers_of(con, sink)}
                    hit = sorted(rset & callers)
                    if not hit:
                        continue
                    shown = ", ".join(f"`{h}`" for h in hit[:3])
                    more = f" +{len(hit) - 3} more" if len(hit) > 3 else ""
                    out.append(R.finding(
                        r, component=comp["name"],
                        evidence=(f"exported {comp['type']} reaches {sink} "
                                  f"via {shown}{more}"),
                        extra={"sink": sink, "via": hit[:10],
                               "reachable_methods": len(rset)}))
                    hits += 1
                    if hits >= cap:
                        break
                if hits >= cap:
                    break
            if hits >= cap:
                for i in range(start, len(out)):
                    out[i].setdefault("detail", {})["truncated"] = True
                out[-1]["evidence"] += f" [truncated at {cap} hits]"
    finally:
        con.close()
    return out
