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
from . import smali_parse as SP

SCHEMA = """
CREATE TABLE methods (
    id   INTEGER PRIMARY KEY,
    sig  TEXT NOT NULL,
    cls  TEXT NOT NULL,
    name TEXT NOT NULL
);
CREATE INDEX methods_cls ON methods(cls);
-- One row per REFERENCE: kind is 'call' | 'string' | 'field-read' |
-- 'field-write' (never a bare 'field': every reader filters on these
-- exact values, so schema comment and queries must agree).
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
# Strict invoke fallback: owner is a DEX type, then name, then full
# descriptor. Invoke rows are normally produced by the shared conservative
# parser (smali_parse); this pattern keeps identity for register-list shapes
# the parser rejects (e.g. `{v0, x1}`). Polymorphic/custom invokes carry
# extra method-handle/proto operands and fall back to the legacy prefix
# match.
_INVOKE_RE = re.compile(
    r"^\s*invoke-\S+\s*\{[^}]*\},\s*"
    r"(L[^;\s]+;)->([^\s(]+)(\([^)]*\)\S+)\s*(?:#.*)?$"
)
# Legacy prefix match for exotic forms (invoke-polymorphic/custom) that the
# strict pattern does not cover. Preserves old behavior, not identity.
_INVOKE_RE_LEGACY = re.compile(r"^\s*invoke-\S+\s*\{[^}]*\},\s*(\S+?)->(\S+?)\(")
_CONST_STR_RE = re.compile(r'^\s*const-string(?:/jumbo)?\s+\S+,\s*"(.*)"\s*$')
_FIELD_RE = re.compile(
    r"^\s*(iget|sget|iput|sput)(?:-wide|-object|-boolean|-byte|-char|-short)?\s+"
    r"\S+,\s*(\S+?)->(\S+?):")
_FIELD_REF_RE = re.compile(
    r"^\s*(?:iget|sget|iput|sput)(?:-wide|-object|-boolean|-byte|-char|-short)?\s+"
    r"\S+,\s*(L[^;\s]+;)->([^:\s]+):(\S+)"
)


def _sig(cls: str, name: str) -> str:
    """Legacy stripped identity (no descriptor). Kept for malformed fallback."""
    name = name.split("(")[0]
    return f"{cls}->{name}" if "->" not in name else name


def _method_sig(owner: str, name: str, descriptor: str) -> str:
    """Return a full DEX method reference; never discard its descriptor."""
    return f"{owner}->{name}{descriptor}"


def _field_sig(owner: str, name: str, descriptor: str) -> str:
    return f"{owner}->{name}:{descriptor}"


def build(decoded: str, *, include_vendor: bool = False,
          stats: dict | None = None) -> sqlite3.Connection:
    """Index a decoded smali tree. Returns an open :memory: connection.

    When `stats` is given, parse-coverage counters are recorded in it
    (`methods`, `calls`, `calls_legacy_fallback`, `field_reads`,
    `field_writes`, `strings`, `malformed_methods`, `unparsed_invokes`).
    """
    con = sqlite3.connect(":memory:")
    con.executescript(SCHEMA)
    mid = 0
    mrows, irows = [], []
    counts = {
        "methods": 0, "calls": 0, "calls_legacy_fallback": 0,
        "field_reads": 0, "field_writes": 0, "strings": 0,
        "malformed_methods": 0, "unparsed_invokes": 0,
        "files_truncated": 0,
    }
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
                    content = fh.read(500_000 + 1)
            except OSError:
                continue
            if len(content) > 500_000:
                content = content[:500_000]
                counts["files_truncated"] += 1
            cls, in_method, meth, meth_id = "", False, "", 0
            for raw in content.splitlines():
                m = _CLASS_RE.match(raw)
                if m:
                    cls = m.group(1)
                    continue
                m = _METHOD_RE.match(raw)
                if m:
                    in_method = True
                    mid += 1
                    meth_id = mid
                    decl = SP.method_declaration(raw)
                    if decl is None:
                        # Malformed declaration: preserve legacy stripped
                        # identity so the method body is still indexed, but
                        # count it for coverage honesty.
                        counts["malformed_methods"] += 1
                        tokens = m.group(1).strip().split()
                        meth = tokens[-1] if tokens else ""
                        full_sig = _sig(cls, meth)
                    else:
                        meth, descriptor = decl
                        full_sig = _method_sig(cls, meth, descriptor)
                    counts["methods"] += 1
                    mrows.append((mid, full_sig, cls, meth))
                    continue
                if _END_METHOD_RE.match(raw):
                    in_method = False
                    continue
                if not in_method or not cls:
                    continue
                if raw.lstrip().startswith("invoke-"):
                    parsed = SP.parse_line(raw)
                    if parsed["status"] == "parsed":
                        ref = parsed["ref"]
                        irows.append((meth_id, "call",
                                      _method_sig(ref["owner"], ref["name"],
                                                  ref["descriptor"])))
                        counts["calls"] += 1
                        continue
                m = _INVOKE_RE.match(raw)
                if m:
                    irows.append((meth_id, "call",
                                  _method_sig(m.group(1), m.group(2), m.group(3))))
                    counts["calls"] += 1
                    continue
                if raw.lstrip().startswith("invoke-"):
                    ml = _INVOKE_RE_LEGACY.match(raw)
                    if ml:
                        # Exotic form (e.g. invoke-polymorphic/custom): keep
                        # legacy stripped target, mark fallback explicitly.
                        irows.append((meth_id, "call",
                                      _sig(ml.group(1), ml.group(2))))
                        counts["calls_legacy_fallback"] += 1
                        continue
                    counts["unparsed_invokes"] += 1
                    continue
                m = _CONST_STR_RE.match(raw)
                if m:
                    irows.append((meth_id, "string", m.group(1)))
                    counts["strings"] += 1
                    continue
                m = _FIELD_REF_RE.match(raw)
                if m:
                    kind = ("field-read" if raw.lstrip().startswith(("iget", "sget"))
                            else "field-write")
                    irows.append((meth_id, kind,
                                  _field_sig(m.group(1), m.group(2), m.group(3))))
                    counts["field_reads" if kind == "field-read" else "field_writes"] += 1
                    continue
                m = _FIELD_RE.match(raw)
                if m:
                    # Field ref without a parseable type: legacy fallback.
                    kind = ("field-read" if m.group(1).startswith(("iget", "sget"))
                            else "field-write")
                    irows.append((meth_id, kind,
                                  _sig(m.group(2), m.group(3))))
    con.executemany("INSERT INTO methods VALUES (?,?,?,?)", mrows)
    con.executemany("INSERT INTO instructions VALUES (?,?,?)", irows)
    con.commit()
    if stats is not None:
        stats.update(counts)
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


def _parse_call_ref(ref: str) -> tuple[str, str, str]:
    """Split `Lowner;->name(descriptor)ret` into (owner, name, descriptor).

    Descriptor is `""` when the ref carries no descriptor (legacy fallback
    rows). Never raises: unparseable refs yield `("", ref, "")`.
    """
    if "->" not in ref:
        return "", ref, ""
    owner, rest = ref.split("->", 1)
    if "(" in rest:
        name, descriptor = rest.split("(", 1)
        return owner, name, "(" + descriptor
    return owner, rest, ""


def _target_matches(ref: str, target: str) -> tuple[bool, str]:
    """Deterministic match of one stored call ref against a sink query.

    Modes (returned as second element on match):
    - `exact-reference`: full `Lowner;->name(descriptor)ret` equality.
    - `owner-name`: exact `Lowner;` + exact method-name equality.
    - `owner-suffix-name`: legacy compat for fragment owners such as
      `Runtime;->exec` (exact method name + owner suffix after `/`).
    - `exact-method-name`: bare token equals the method name.
    - `exact-class-name`: bare token equals the owner simple name or full
      owner (covers `DexClassLoader` style class sinks).

    Never substring-matches a method name: `loadUrl` does not match
    `preloadUrl` or `loadUrlUnsafe`.
    """
    ref_owner, ref_name, _ref_desc = _parse_call_ref(ref)
    if "->" in target:
        owner_q, name_q = target.split("->", 1)
        name_base = name_q.split("(", 1)[0]
        has_descriptor = "(" in name_q
        owner_is_canonical = owner_q.startswith("L") and owner_q.endswith(";")
        if owner_is_canonical and has_descriptor:
            if ref == target:
                return True, "exact-reference"
            return False, "exact-reference"
        if has_descriptor:
            # Fragment owner + descriptor: exact ref equality only when the
            # stored ref matches verbatim; otherwise fall through to the
            # owner/name checks below on the base name.
            if ref == target:
                return True, "exact-reference"
        if name_base and ref_name == name_base:
            if ref_owner == owner_q:
                return True, "owner-name"
            # Legacy fragment owners (no leading L): match on owner suffix
            # so `Runtime;->exec` finds `Ljava/lang/Runtime;->exec(...)`.
            # Segment-aligned: `MyRuntime;` is NOT a `Runtime;` match.
            frag = owner_q[1:] if owner_q.startswith("L") else owner_q
            if frag and (ref_owner == frag or ref_owner.endswith("/" + frag)):
                return True, "owner-suffix-name"
        return False, "owner-name"
    # Bare token: exact method name OR exact owning-class name.
    if ref_name == target:
        return True, "exact-method-name"
    simple = ref_owner.rsplit("/", 1)[-1].rstrip(";")
    if target and (simple == target or ref_owner == target):
        return True, "exact-class-name"
    return False, "exact-method-name"


def callers_of(con: sqlite3.Connection, target: str) -> list[dict]:
    """Every method containing a call to target (exact, deterministic).

    A fully qualified target containing `->` is matched per
    `_target_matches`; a bare method/class name is matched against the
    parsed method-name/class token, never as a substring. Each result
    carries `matched_target` and `match_mode` for evidence.
    """
    rows = con.execute(
        "SELECT DISTINCT m.sig, i.target FROM instructions i "
        "JOIN methods m ON m.id = i.method_id "
        "WHERE i.kind = 'call' ORDER BY m.sig"
    ).fetchall()
    by_caller: dict[str, tuple[str, str]] = {}
    for caller, ref in rows:
        ok, mode = _target_matches(ref, target)
        if ok and caller not in by_caller:
            by_caller[caller] = (ref, mode)
    return [{"caller": sig, "matched_target": by_caller[sig][0],
             "match_mode": by_caller[sig][1]}
            for sig in sorted(by_caller)]


_DEFAULT_SINKS = ("loadUrl", "addJavascriptInterface", "Runtime;->exec",
                  "DexClassLoader", "PathClassLoader")


def _class_seeds(con: sqlite3.Connection, cls: str) -> list[str]:
    """Method sigs of `cls` itself plus its nested `$` classes.

    Exact matching only: SQLite `LIKE` is case-insensitive and treats `_`
    as a wildcard, so `com.a.B_C` could seed an unrelated `Lcom/a/BXC$…;`.
    """
    return [s for (s,) in con.execute(
        "SELECT sig FROM methods WHERE cls = ?"
        " OR (substr(cls, 1, ?) = ? AND substr(cls, -1, 1) = ';')"
        " ORDER BY sig",
        (cls + ";", len(cls) + 1, cls + "$")).fetchall()]


def _parse_status(build_stats: dict) -> tuple[bool, str]:
    """Whether parser output is exact; otherwise a human reason.

    Legacy-fallback invokes keep stripped (descriptor-less) identity and
    unparsed/malformed inputs are dropped: any of them makes reachability
    approximate, never apparently complete. The fallback rows themselves are
    preserved (behavior unchanged).
    """
    problems = []
    if build_stats.get("files_truncated"):
        problems.append(f"{build_stats['files_truncated']} file(s) truncated at the 500 KB read cap")
    if build_stats.get("malformed_methods"):
        problems.append(f"{build_stats['malformed_methods']} malformed method declaration(s)")
    if build_stats.get("unparsed_invokes"):
        problems.append(f"{build_stats['unparsed_invokes']} unparsed invoke(s)")
    if build_stats.get("calls_legacy_fallback"):
        problems.append(f"{build_stats['calls_legacy_fallback']} approximate fallback invoke(s)")
    if problems:
        return False, "parser coverage gaps: " + "; ".join(problems)
    return True, ""


def check_reachability(rules: list, decoded: str, man: dict,
                       limit: int = 15, coverage: dict | None = None) -> list[dict]:
    """Exported entry points that can reach sensitive sinks (high).

    When `coverage` is given it receives `rules_evaluated`,
    `traversal_truncated_any`, `hit_cap_truncated_any`, and the `build_stats`
    from graph construction so callers can report parse completeness.
    Every finding carries `detail.parse_coverage` with those build counts.
    """
    from . import rules as R
    if not decoded or not os.path.isdir(decoded):
        if coverage is not None:
            coverage.update({"rules_evaluated": 0, "traversal_truncated_any": False,
                             "hit_cap_truncated_any": False, "build_stats": {}})
        return []
    out: list[dict] = []
    comps = [c for c in man.get("components", []) if c.get("exported")]
    if not comps:
        if coverage is not None:
            coverage.update({"rules_evaluated": 0, "traversal_truncated_any": False,
                             "hit_cap_truncated_any": False, "build_stats": {}})
        return out
    build_stats: dict = {}
    con = build(decoded, stats=build_stats)
    parse_exact, parse_reason = _parse_status(build_stats)
    parse_coverage = {
        "methods": build_stats.get("methods", 0),
        "calls": build_stats.get("calls", 0),
        "calls_legacy_fallback": build_stats.get("calls_legacy_fallback", 0),
        "unparsed_invokes": build_stats.get("unparsed_invokes", 0),
        "malformed_methods": build_stats.get("malformed_methods", 0),
        "files_truncated": build_stats.get("files_truncated", 0),
    }
    traversal_truncated_any = False
    hit_cap_truncated_any = False
    try:
        for r in rules:
            sinks = r.params.get("sinks", list(_DEFAULT_SINKS))
            cap = int(r.params.get("cap", limit))
            try:
                reach_limit = int(r.params.get("reach_limit",
                                               r.params.get("traversal_limit", 5000)))
            except (TypeError, ValueError):
                reach_limit = 5000
            if reach_limit <= 0:
                reach_limit = 5000
            hits = 0
            start = len(out)
            rule_truncated = False
            rule_reachable_methods = 0
            for comp in comps:
                cls = "L" + comp["name"].replace(".", "/")
                seeds = _class_seeds(con, cls)
                if not seeds:
                    continue
                reach_result = reachable(con, seeds, limit=reach_limit)
                rset = {x["sig"] for x in reach_result["rows"]}
                rule_truncated = rule_truncated or reach_result["truncated"]
                traversal_truncated_any = traversal_truncated_any or reach_result["truncated"]
                rule_reachable_methods = max(rule_reachable_methods, len(rset))
                for sink in sinks:
                    callers = {x["caller"] for x in callers_of(con, sink)}
                    hit = sorted(rset & callers)
                    if not hit:
                        continue
                    shown = ", ".join(f"`{h}`" for h in hit[:3])
                    more = f" +{len(hit) - 3} more" if len(hit) > 3 else ""
                    is_partial = reach_result["truncated"] or not parse_exact
                    reason = ("reachable-method limit reached"
                              if reach_result["truncated"] else parse_reason)
                    out.append(R.finding(
                        r, component=comp["name"],
                        evidence=(f"exported {comp['type']} reaches {sink} "
                                  f"via {shown}{more}"),
                        extra={"sink": sink, "via": hit[:10],
                               "reachable_methods": len(rset),
                               "parse_coverage": dict(parse_coverage),
                               "analysis": {
                                   "status": "partial" if is_partial else "complete",
                                   "truncated": reach_result["truncated"],
                                   "limit": reach_result["limit"],
                                   "reason": reason,
                               }}))
                    hits += 1
                    if hits >= cap:
                        break
                if hits >= cap:
                    break
            if hits >= cap:
                hit_cap_truncated_any = True
                for i in range(start, len(out)):
                    out[i].setdefault("detail", {})["truncated"] = True
                out[-1]["evidence"] += f" [truncated at {cap} hits]"
            if hits == 0 and rule_truncated:
                # No-hit from a truncated graph is inconclusive, never clean.
                # One aggregated record per rule (not per component).
                cov = R.finding(
                    r, component="",
                    evidence=("reachability traversal truncated at "
                              f"{reach_limit} methods; no sink observed within "
                              "the truncated closure — inconclusive, not a clean result"),
                    extra={"sink": None, "via": [],
                           "reachable_methods": rule_reachable_methods,
                           "parse_coverage": dict(parse_coverage),
                           "coverage": "inconclusive-no-hit-truncated",
                           "analysis": {
                               "status": "partial",
                               "truncated": True,
                               "limit": reach_limit,
                               "reason": "reachable-method limit reached",
                           }})
                cov["severity"] = "info"
                cov["severity_adjusted"] = f"{r.severity} -> info"
                out.append(cov)
        if coverage is not None:
            coverage.update({"rules_evaluated": len(rules),
                             "traversal_truncated_any": traversal_truncated_any,
                             "hit_cap_truncated_any": hit_cap_truncated_any,
                             "build_stats": dict(build_stats)})
    finally:
        con.close()
    return out
