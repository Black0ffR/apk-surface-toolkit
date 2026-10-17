"""Intra-method smali register taint: Intent sources -> dangerous sinks.

Matching is structured (TF-03): rule entries are literal callee names by
default, owner-scoped when an owner is given, or explicit regex when
requested (`"match": "regex"`). Instruction decoding is delegated to the
shared conservative parser (smali_parse): unmodeled instruction forms are
counted as coverage gaps and never silently misread.

Flow analysis (TF-02 Stage 3) is a worklist fixed point over the method's
basic-block CFG (smali_cfg). Register states are three-valued: untainted
(absent), tainted (a bounded tuple of source entries), or unknown (an
unmodeled value, e.g. an array element); joins keep unknown and taint
conservatively. Unreachable blocks are never analysed, unresolved targets
never get invented successors, and a bounded visit budget stops runaway
convergence by marking coverage incomplete rather than claiming success.

Interprocedural summaries (TF-02 Stage 4) are opt-in per rule
(`"interprocedural": true`). A bounded fix point over referenced in-tree
methods computes parameter->return dependencies, parameter->sink relations,
internally produced sources, and an explicit unknown/incomplete flag. Calls
to unresolved callees, unverifiable sanitizers, ambiguous identities, and
non-convergent summaries are reported as gaps (counters + partial stage),
never as clean results; findings stay candidates.
"""
from __future__ import annotations

import os
import re

from . import rules as R
from . import smali_cfg as CFG
from . import smali_parse as SP
from .analyzer import VENDOR_PREFIXES

_DEFAULT_SOURCES = ("getIntent", "getData", "getStringExtra",
                    "getParcelableExtra", "getSerializableExtra")
_DEFAULT_SINKS = ("loadUrl", "addJavascriptInterface", "startActivity",
                  "startService", "sendBroadcast", "setClass")

_METHOD_RE = re.compile(r"^\s*\.method\b", re.I)
_END_METHOD_RE = re.compile(r"^\s*\.end\s+method", re.I)
_CLASS_RE = re.compile(r"^\s*\.class\b.*?(L[^;]+;)")
_RETURN_RE = re.compile(r"^\s*return(?:-(?:object|wide))?\s+([vp]\d+)", re.I)
_DIRECTIVE_RE = re.compile(r"^\s*\.(registers|locals)\s+(\d+)\s*(?:#.*)?$")
_CLASS_DESC_RE = re.compile(r"L[^;]*;")

ANALYSIS_KIND = "intra_method_register_taint"

TAINT_LIMITATIONS = [
    "intra-method CFG fixed-point over basic blocks; not interprocedural",
    "unreachable blocks are not analysed; missing branch targets are gaps, not invented edges",
    "a bounded per-block visit budget can stop convergence and is reported as incomplete",
    "field, array, collection, aliasing, and exception-handler flows are not modeled; array reads yield unknown",
    "wide (64-bit) values tracked as adjacent register pairs by name, not by type",
    "sanitizers/transformers are not modeled unless added as explicit rules",
]

TAINT_INTERPROCEDURAL_LIMITATIONS = [
    "interprocedural summaries are opt-in and bounded (pass cap); unresolved callees, "
    "ambiguous identities, and incomplete summaries stay unknown, never clean",
    "only declared parameters are followed across method boundaries; receiver flows are "
    "tracked by position, field and container flows remain unmodeled",
    "sanitizers are honored only when their in-tree body is resolvable; sanitizer calls "
    "inside summarized helpers are treated as ordinary calls (no tag propagation)",
    "call results from unresolved callees are unknown; side effects of unresolved void "
    "calls are not modeled",
]

CONFIDENCE_CANDIDATE = "candidate"

ENTRY_CAP = 8
_SUMMARY_PASS_CAP = 8
_RELATION_CAP = 64
_FIXED_POINT_VISIT_FACTOR = 16
_FIXED_POINT_VISIT_SLACK = 64

_INTEROP_COUNTERS = ("unresolved_calls", "sanitizers_unverified",
                     "summaries_incomplete", "ambiguous_methods",
                     "sanitizer_passages", "summaries_built")

# Intent setters that rebind a navigation target. When one appears between
# a `getIntent()` source and a start* sink, the launched component is no
# longer the caller's own intent: it is a genuine redirect, not the benign
# `finish(); startActivity(getIntent())` self-relaunch idiom.
_INTENT_REBIND = frozenset({
    "setComponent", "setClassName", "setClass", "setData", "setDataAndType",
    "setAction", "setPackage", "setType", "setIdentifier",
})
_SELF_RELAUNCH_SINKS = frozenset({
    "startActivity", "startActivityForResult", "startActivityIfNeeded",
    "startNextMatchingActivity", "startService",
})


class _UnknownType:
    """Three-valued marker: the value may or may not be tainted (unmodeled).

    Unknown is kept distinct from "untainted" (register absent) so a lost
    precision never silently becomes a negative claim; joins never degrade
    unknown into untainted.
    """
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "UNKNOWN"


UNKNOWN = _UnknownType()


def analysis_scope(interprocedural: bool = False) -> dict:
    """Additive descriptor of this module's analysis scope and limits."""
    limitations = list(TAINT_LIMITATIONS)
    if interprocedural:
        limitations = [lim for lim in limitations
                       if "not interprocedural" not in lim]
        limitations += list(TAINT_INTERPROCEDURAL_LIMITATIONS)
    return {
        "kind": ANALYSIS_KIND,
        "scope": "cfg-smali-method",
        "interprocedural": bool(interprocedural),
        "control_flow_aware": True,
        "confidence": CONFIDENCE_CANDIDATE,
        "limitations": limitations,
    }


def _wide_pair(reg: str) -> list[str]:
    """Adjacent registers holding one 64-bit value (`v0` -> `[v0, v1]`).

    Dalvik wide values (long/double) occupy two adjacent registers. Narrow
    registers map to themselves. Unparseable names map to themselves so the
    caller still kills/propagates the named register.
    """
    m = re.fullmatch(r"([vp])(\d+)", reg)
    if not m:
        return [reg]
    return [reg, f"{m.group(1)}{int(m.group(2)) + 1}"]


def compile_matchers(entries, field: str = "sources") -> list[dict]:
    """Normalize rule matcher entries into matcher dicts (TF-03/TF-04).

    Accepts legacy bare strings (literal callee-name matching) and mappings
    {owner?, name, match?, argument_indexes?, context? (sinks) / contexts?
    (sanitizers)}. Raises ValueError/re.error on malformed entries; scan()
    turns that into a rule finding, never a crash.
    """
    out: list[dict] = []
    for index, entry in enumerate(entries or ()):
        if isinstance(entry, str):
            name, owner, mode = entry, None, "name"
        elif isinstance(entry, dict):
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError(f"{field}[{index}] missing name")
            owner = entry.get("owner")
            mode = entry.get("match") or ("owner-name" if owner else "name")
        else:
            raise ValueError(f"{field}[{index}] must be a string or a mapping")
        if mode not in ("name", "owner-name", "regex"):
            raise ValueError(f"{field}[{index}] bad match mode {mode!r}")
        matcher = {"mode": mode, "owner": owner, "name": name, "regex": None,
                   "argument_indexes": None, "context": None, "contexts": None}
        if mode == "regex":
            matcher["regex"] = re.compile(name, re.I)
        if isinstance(entry, dict) and "argument_indexes" in entry:
            if field not in ("sinks", "sanitizers"):
                raise ValueError(
                    f"{field}[{index}] argument_indexes is only valid for sinks")
            try:
                matcher["argument_indexes"] = [int(i) for i in entry["argument_indexes"]]
            except (TypeError, ValueError):
                raise ValueError(f"{field}[{index}] bad argument_indexes")
        if isinstance(entry, dict):
            context = entry.get("context")
            if isinstance(context, str) and context.strip():
                matcher["context"] = context
            contexts = entry.get("contexts")
            if isinstance(contexts, list) and contexts:
                matcher["contexts"] = tuple(str(c) for c in contexts)
        out.append(matcher)
    return out


def _match_call(matcher: dict, owner: str, name: str) -> bool:
    """True when a call (owner, callee name) matches a compiled matcher.

    Name mode matches the callee name only; owner-name additionally requires
    an exact owner descriptor; regex searches the callee name.
    """
    mode = matcher["mode"]
    if mode == "regex":
        return bool(matcher["regex"].search(name))
    if matcher["name"] != name:
        return False
    if mode == "owner-name":
        return matcher["owner"] is not None and owner == matcher["owner"]
    return True


def _match_info(matcher: dict) -> dict:
    return {"mode": matcher["mode"], "owner": matcher["owner"],
            "name": matcher["name"]}


def argument_registers(registers: list[str], indexes) -> list[str]:
    """Select raw invoke-register positions for a sink's argument_indexes.

    The index counts registers exactly as written in the invoke operand
    list: for virtual/interface/direct calls position 0 is the receiver and
    the first declared argument is position 1; static calls have no receiver,
    so position 0 is the first declared argument. Out-of-range positions
    select nothing. This receiver-inclusive convention is normalized here
    and nowhere else; `indexes=None` means "any register".
    """
    if indexes is None:
        return list(registers)
    return [registers[i] for i in indexes if 0 <= i < len(registers)]


def _entry_key(entry: dict) -> tuple:
    matcher = entry.get("matcher") or {}
    return (entry.get("line", -1), entry.get("method") or "",
            entry.get("owner") or "", matcher.get("mode") or "",
            matcher.get("name") or "",
            entry.get("kind") or "src", entry.get("index", -1),
            entry.get("file") or "", entry.get("sanitized") or (),
            tuple(entry.get("via") or ()))


def _sorted_entries(entries) -> tuple:
    return tuple(sorted(entries, key=_entry_key)[:ENTRY_CAP])


def _merge_entries(groups) -> tuple:
    seen: dict = {}
    for group in groups:
        for entry in group:
            seen.setdefault(_entry_key(entry), entry)
    return tuple(seen[key] for key in sorted(seen))[:ENTRY_CAP]


def _join_values(values) -> object:
    """Join register values from merging paths (three-valued lattice).

    U+U=U, U+T=T, U+?=?, T+T=merge, T+?=T, ?+?=? where U is absence from the
    value list. Unknown never degrades to untainted.
    """
    taints = [v for v in values if isinstance(v, tuple)]
    if taints:
        return _merge_entries(taints)
    if any(v is UNKNOWN for v in values):
        return UNKNOWN
    return None


def _join_states(states: list[dict]) -> dict:
    out: dict = {}
    regs: set = set()
    for state in states:
        regs.update(state)
    for reg in regs:
        value = _join_values([s[reg] for s in states if reg in s])
        if value is not None:
            out[reg] = value
    return out


def _taint_entry(pending: dict, reg: str) -> dict:
    return {"line": pending["line"], "method": pending["method"],
            "owner": pending["owner"], "matcher": pending["matcher"],
            "path": [reg]}


def _transfer(block, items: list[dict], in_state: dict,
              src_matchers: list[dict], sink_matchers: list[dict]):
    """Transfer one basic block over an in-state; returns (out_state, hits).

    Keeps the historical per-instruction semantics (source->move-result
    pairing within the block, const/new-*/move kills, wide pairs by name).
    Array reads (`aget*`) yield unknown: the element value is unmodeled, so
    the read must not be treated as a clean kill.
    """
    state = dict(in_state)
    hits: list[dict] = []
    pending_src: dict | None = None
    for ln in range(block.start_line, block.end_line + 1):
        item = items[ln]
        if item["status"] != SP.PARSED:
            continue
        opcode = item["opcode"]
        line_no = item["line"]
        if opcode.startswith("invoke"):
            ref = item["ref"]
            owner, name = ref["owner"], ref["name"]
            source = next((m for m in src_matchers if _match_call(m, owner, name)),
                          None)
            if source is not None:
                pending_src = {"line": line_no, "method": name, "owner": owner,
                               "matcher": source}
                continue
            pending_src = None
            sink = next((m for m in sink_matchers if _match_call(m, owner, name)),
                        None)
            if sink is not None:
                for reg in argument_registers(item["registers"],
                                              sink["argument_indexes"]):
                    value = state.get(reg)
                    if isinstance(value, tuple) and value:
                        t = value[0]
                        hits.append({
                            "src_line": t["line"],
                            "src_method": t["method"],
                            "sink_line": line_no,
                            "sink": name,
                            "reg": reg,
                            "src_owner": t["owner"],
                            "sink_owner": owner,
                            "source_match": _match_info(t["matcher"]),
                            "sink_match": _match_info(sink),
                            "path": t.get("path") or [reg],
                        })
                        break
            continue
        if opcode.startswith("move-result"):
            reg = item["registers"][0]
            dsts = _wide_pair(reg) if "wide" in opcode else [reg]
            if pending_src is not None:
                for d in dsts:
                    state[d] = (_taint_entry(pending_src, d),)
                pending_src = None
            else:
                # A result from an unmatched callee is unknown, not clean: it
                # must not be treated as a proven-untainted kill.
                for d in dsts:
                    state[d] = UNKNOWN
            continue
        if opcode.startswith(("const", "new-instance", "new-array")):
            reg = item["registers"][0]
            for d in (_wide_pair(reg) if "wide" in opcode else [reg]):
                state.pop(d, None)
            continue
        if opcode.startswith("aget"):
            reg = item["registers"][0]
            for d in (_wide_pair(reg) if "wide" in opcode else [reg]):
                state[d] = UNKNOWN
            continue
        if opcode == "fill-array-data":
            state[item["registers"][0]] = UNKNOWN
            continue
        if opcode == "move-exception":
            # A caught exception object is a fresh value, not one of our
            # sources: a clean kill (mirrors new-instance). Must precede the
            # generic `move` branch (its opcode starts with "move").
            state.pop(item["registers"][0], None)
            continue
        if opcode.startswith(("iget", "sget")):
            # Field reads are unmodeled (like array reads): unknown, never a
            # proven-clean kill.
            reg = item["registers"][0]
            for d in (_wide_pair(reg) if "wide" in opcode else [reg]):
                state[d] = UNKNOWN
            continue
        if opcode.startswith(("iput", "sput", "aput")):
            # Field/array writes define no local register.
            continue
        if opcode.startswith("filled-new-array"):
            pending_src = None
            continue
        if opcode.split("/")[0] in SP.PROPAGATE_OPS:
            # Arithmetic/shift/convert/compare/array-length/instance-of: the
            # destination is derived from its sources, so taint propagates
            # (union of source entries); with no taint it is a clean def.
            regs = item["registers"]
            dst, srcs = regs[0], regs[1:]
            wide = "-long" in opcode or "-double" in opcode
            dsts = _wide_pair(dst) if wide else [dst]
            value = None
            unknown = False
            for s in srcs:
                for ss in (_wide_pair(s) if wide else [s]):
                    v = state.get(ss)
                    if isinstance(v, tuple) and v:
                        value = _sorted_entries(list(value or ()) + list(v))
                    elif v is UNKNOWN:
                        unknown = True
            for d in dsts:
                state.pop(d, None)
            if value is not None:
                for d in dsts:
                    state[d] = _sorted_entries(
                        {**e, "path": list(e.get("path") or []) + [d]}
                        for e in value)
            elif unknown:
                for d in dsts:
                    state[d] = UNKNOWN
            continue
        if opcode.startswith("move"):
            dst, src = item["registers"]
            dsts = _wide_pair(dst) if "wide" in opcode else [dst]
            srcs = _wide_pair(src) if "wide" in opcode else [src]
            value = None
            for s in srcs:
                v = state.get(s)
                if isinstance(v, tuple) and v:
                    value = v
                    break
            if value is None and any(state.get(s) is UNKNOWN for s in srcs):
                value = UNKNOWN
            for d in dsts:
                state.pop(d, None)
            if value is UNKNOWN:
                for d in dsts:
                    state[d] = UNKNOWN
            elif value is not None:
                for d in dsts:
                    state[d] = _sorted_entries(
                        {**e, "path": list(e.get("path") or []) + [d]}
                        for e in value)
    return state, hits


def _fixed_point(cfg, items: list[dict], src_matchers: list[dict],
                 sink_matchers: list[dict], visit_cap=None, *,
                 transfer=None, entry_state=None,
                 out_result: dict | None = None) -> tuple:
    """Worklist fixed point; returns (hits, capped).

    Only blocks reachable from the entry get an in-state (a missing
    predecessor state is never treated as untainted). Reaching the per-block
    visit cap stops iteration and reports `capped`; hits found before the cap
    are kept but coverage is incomplete. `transfer` overrides the per-block
    transfer function (interprocedural modes); `entry_state` seeds the entry
    block (e.g. parameter values); `out_result` receives the final out-states.
    """
    if transfer is None:
        def transfer(block, items_, in_state):
            return _transfer(block, items_, in_state, src_matchers,
                             sink_matchers)
    seed = dict(entry_state) if entry_state else {}
    block_count = len(cfg.blocks)
    cap = (visit_cap if visit_cap is not None
           else _FIXED_POINT_VISIT_FACTOR * block_count + _FIXED_POINT_VISIT_SLACK)
    preds: dict[str, list[str]] = {b.block_id: [] for b in cfg.blocks}
    for block in cfg.blocks:
        for succ in block.successors:
            preds[succ].append(block.block_id)
    out_states: dict[str, dict] = {}
    visits = {b.block_id: 0 for b in cfg.blocks}
    hits: list[dict] = []
    seen_hits: set = set()
    dirty = {cfg.entry}
    capped = False
    while dirty:
        for block in cfg.blocks:
            bid = block.block_id
            if bid not in dirty:
                continue
            if visits[bid] >= cap:
                capped = True
                dirty.clear()
                break
            visits[bid] += 1
            pred_outs = [out_states[p] for p in preds[bid] if p in out_states]
            if bid == cfg.entry:
                pred_outs.append(dict(seed))
            if not pred_outs:
                dirty.discard(bid)
                continue
            in_state = _join_states(pred_outs)
            new_out, new_hits = transfer(block, items, in_state)
            for hit in new_hits:
                if hit.get("event"):
                    key = ("event", hit["event"], hit.get("file", ""),
                           hit.get("line", -1), hit.get("reg", ""),
                           hit.get("extra_key") or ())
                else:
                    key = (hit["src_line"], hit["sink_line"], hit["sink"],
                           hit["reg"], hit["src_method"], hit["sink_owner"],
                           hit.get("src_file") or "")
                if key not in seen_hits:
                    seen_hits.add(key)
                    hits.append(hit)
            dirty.discard(bid)
            if out_states.get(bid) != new_out:
                out_states[bid] = new_out
                for succ in block.successors:
                    dirty.add(succ)
    if out_result is not None:
        out_result.update(out_states)
    return hits, capped


def _coverage(lines) -> tuple:
    """Parse one method body into (items, cfg, coverage counters).

    `unsupported_instructions` / `malformed_instructions` come from the
    shared parser; `missing_labels` / `unresolved_switches` from the CFG
    builder; `capped` is filled by the caller's fixed point.
    """
    lines = list(lines or ())
    items = SP.parse_lines(lines)
    full = {"unsupported_instructions": 0, "malformed_instructions": 0,
            "missing_labels": 0, "unresolved_switches": 0, "capped": 0}
    for item in items:
        if item["status"] == SP.UNSUPPORTED:
            full["unsupported_instructions"] += 1
        elif item["status"] == SP.MALFORMED:
            full["malformed_instructions"] += 1
    cfg = CFG.build(lines)
    full["missing_labels"] = len(cfg.missing_labels)
    full["unresolved_switches"] = cfg.unresolved_switches
    return items, cfg, full


def _analyze_method(lines, src_matchers: list[dict],
                    sink_matchers: list[dict], counters: dict | None = None,
                    visit_cap=None) -> list[dict]:
    """CFG fixed-point scan for one .method body (TF-02 Stage 3).

    Returns the hits (same shape as before). `counters`, when given,
    accumulates the full per-method coverage counter set:
    `unsupported_instructions`, `malformed_instructions`, `missing_labels`,
    `unresolved_switches`, `capped`. `visit_cap` overrides the per-block visit
    budget (default 16*blocks+64); reaching it sets `capped` and stops the
    fixed point with partial results.
    """
    items, cfg, full = _coverage(lines)
    hits: list[dict] = []
    if cfg.blocks:
        hits, capped = _fixed_point(cfg, items, src_matchers, sink_matchers,
                                    visit_cap=visit_cap)
        full["capped"] = 1 if capped else 0
    if counters is not None:
        for key, value in full.items():
            counters[key] = counters.get(key, 0) + value
    return hits


def _scan_method(lines: list[str], src_matchers: list[dict],
                 sink_matchers: list[dict], counters: dict | None = None) -> list[dict]:
    """Compatibility wrapper over `_analyze_method`.

    `counters`, when given, accumulates exactly the two legacy counter keys
    this API historically exposed; new callers should use `_analyze_method`
    for the full coverage counter set.
    """
    full: dict = {}
    hits = _analyze_method(lines, src_matchers, sink_matchers, full)
    if counters is not None:
        for key in ("unsupported_instructions", "malformed_instructions"):
            counters[key] = counters.get(key, 0) + full[key]
    return hits


# ---------------------------------------------------------------------------
# TF-02 Stage 4: interprocedural summaries (opt-in via rule param).
#
# A bounded fix point over referenced in-tree methods computes, per method
# identity (owner + name + descriptor): which declared parameters influence
# the return value, internally produced source entries that can be returned,
# parameter->sink relations, and an explicit complete/incomplete flag.
# UNKNOWN semantics are preserved across method boundaries: an unresolved
# callee result, an unusable sanitizer, an ambiguous identity, or a
# non-convergent summary yields UNKNOWN, never "clean".
# ---------------------------------------------------------------------------

_MISSING = object()


def _iter_smali_files(base: str, include_vendor: bool, skip_dirs: set) -> list:
    """Sorted .smali file list with the same vendor/hidden/skip filters."""
    paths: list = []
    for dirpath, dirnames, files in os.walk(base):
        rel = os.path.relpath(dirpath, base)
        if not include_vendor and any(
                rel == vp or rel.startswith(vp + os.sep)
                for vp in VENDOR_PREFIXES):
            dirnames[:] = []
            continue
        dirnames[:] = sorted(d for d in dirnames
                             if not d.startswith(".") and d not in skip_dirs)
        if any(part in skip_dirs for part in rel.split(os.sep)):
            continue
        for fn in sorted(files):
            if fn.endswith(".smali"):
                paths.append(os.path.join(dirpath, fn))
    return paths


_READ_CAP = 500_000


def _read_capped(path: str):
    """Read up to `_READ_CAP` chars; second element flags real truncation.

    Reads cap+1 so an exactly-cap-sized file is not misreported as
    truncated. Never raises: unreadable files yield (None, False).
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read(_READ_CAP + 1)
    except OSError:
        return None, False
    if len(raw) > _READ_CAP:
        return raw[:_READ_CAP], True
    return raw, False


def _read_file(path: str):
    content, _truncated = _read_capped(path)
    return content


def _iter_method_blocks(content: str):
    """Yield (base_ln, decl_line, lines) for each .method block in order."""
    block = None
    decl_line = ""
    base_ln = -1
    for ln, raw in enumerate(content.splitlines()):
        if _METHOD_RE.match(raw):
            if block is not None:
                yield base_ln, decl_line, block
            block = [raw]
            decl_line = raw
            base_ln = ln
            continue
        if block is not None:
            block.append(raw)
            if _END_METHOD_RE.match(raw):
                yield base_ln, decl_line, block
                block = None
    if block is not None:
        yield base_ln, decl_line, block


def _class_of(content: str):
    """Class descriptor from the `.class` directive (callgraph convention)."""
    for raw in content.splitlines():
        m = _CLASS_RE.match(raw)
        if m:
            return m.group(1)
    return None


def _is_static_decl(decl: str) -> bool:
    return re.search(r"\bstatic\b", decl.split("(", 1)[0]) is not None


def _param_widths(descriptor: str):
    """Per-parameter register widths from a method descriptor, or None."""
    desc = descriptor or ""
    if not desc.startswith("("):
        return None
    widths: list = []
    i = 1
    while i < len(desc) and desc[i] != ")":
        start = i
        c = desc[i]
        if c == "[":
            while i < len(desc) and desc[i] == "[":
                i += 1
            if i >= len(desc):
                return None
            c = desc[i]
        if c == "L":
            j = desc.find(";", i)
            if j < 0:
                return None
            i = j + 1
        elif c in "BCSIFZJD":
            i += 1
        else:
            return None
        widths.append(2 if (i - start == 1 and c in "JD") else 1)
    if i >= len(desc) or desc[i] != ")":
        return None
    return widths


def _param_map(lines, is_static: bool) -> tuple:
    """({param index: register names}, ok) for one method body.

    Registers are exposed under both their `pN` names and, when the
    `.locals`/`.registers` directive can be read consistently, their `vN`
    aliases. `ok` is False when the directive is missing or inconsistent;
    callers then mark the summary incomplete instead of guessing a register
    layout.
    """
    decl = next((raw for raw in lines if _METHOD_RE.match(raw)), "")
    parsed = SP.method_declaration(decl)
    widths = _param_widths(parsed[1]) if parsed else None
    if widths is None:
        return {}, False
    offset = 0 if is_static else 1
    directive = None
    for raw in lines:
        m = _DIRECTIVE_RE.match(raw)
        if m:
            directive = m.group(1).lower(), int(m.group(2))
            break
    ok = directive is not None
    base_v = None
    if directive is not None:
        kind, value = directive
        if kind == "registers":
            value = value - (sum(widths) + offset)
        if value < 0:
            ok = False
        else:
            base_v = value
    mapping: dict = {}
    for index, width in enumerate(widths):
        slot = sum(widths[:index]) + offset
        names: list = []
        for word in range(width):
            names.append(f"p{slot + word}")
            if base_v is not None:
                names.append(f"v{base_v + slot + word}")
        mapping[index] = tuple(names)
    return mapping, ok


def _seed_params(mapping: dict, file: str, sig: str) -> dict:
    """Entry state seeding every parameter register with its param entry."""
    state: dict = {}
    for index, names in mapping.items():
        entry = {"line": -1, "method": sig, "owner": None, "matcher": None,
                 "kind": "param", "index": index, "file": file, "via": (),
                 "sanitized": None, "path": [names[0]]}
        value = (entry,)
        for name in names:
            state[name] = value
    return state


def _coverage_pieces(counters: dict) -> list:
    """Human-readable per-method coverage gap pieces (stable strings)."""
    pieces: list = []
    legacy: list = []
    if counters.get("unsupported_instructions"):
        legacy.append(f"{counters['unsupported_instructions']} unsupported")
    if counters.get("malformed_instructions"):
        legacy.append(f"{counters['malformed_instructions']} malformed")
    if legacy:
        pieces.append("method coverage gaps: " + ", ".join(legacy)
                      + " instruction(s)")
    if counters.get("missing_labels"):
        pieces.append(f"{counters['missing_labels']} missing label(s)")
    if counters.get("unresolved_switches"):
        pieces.append(
            f"{counters['unresolved_switches']} unresolved switch(es)")
    if counters.get("capped"):
        pieces.append("fixed-point visit cap reached")
    return pieces


def _coverage_problems(coverage: dict, param_ok: bool) -> list:
    """Reasons a summary cannot be trusted to be complete."""
    problems = list(_coverage_pieces(coverage))
    if not param_ok:
        problems.append("param registers unverifiable")
    return problems


def _call_sig(key: tuple) -> str:
    return f"{key[0]}->{key[1]}{key[2]}"


def _operand_pos(item: dict, key: tuple, param_index: int):
    """Caller operand register position for a callee parameter index."""
    widths = _param_widths(key[2])
    if widths is None or param_index >= len(widths):
        return None
    static = item.get("invoke_static")
    if static is None:
        return None
    pos = sum(widths[:param_index]) + (0 if static else 1)
    if pos >= len(item["registers"]):
        return None
    return pos


def _rebind_lines(items, base_ln: int) -> list:
    """Absolute lines of Intent-rebinding invokes in a parsed method body."""
    out = []
    for it in items or ():
        if it.get("status") != SP.PARSED:
            continue
        ref = it.get("ref")
        if (ref is not None
                and str(it.get("opcode", "")).startswith("invoke")
                and ref.get("name") in _INTENT_REBIND):
            out.append(base_ln + it["line"])
    return out


def _self_relaunch(source_match, sink_match, src_line, sink_line,
                   rebind_lines) -> bool:
    """True for the benign `startActivity(getIntent())` self-relaunch idiom.

    A flow qualifies only when the source is `getIntent()` (the caller's own
    intent), the sink is a component-start entry point, and no Intent
    rebinding setter runs between them. Anything else stays a redirect.
    """
    if (source_match or {}).get("name") != "getIntent":
        return False
    if (sink_match or {}).get("name") not in _SELF_RELAUNCH_SINKS:
        return False
    if not isinstance(src_line, int) or not isinstance(sink_line, int):
        return False
    lo, hi = (src_line, sink_line) if src_line <= sink_line \
        else (sink_line, src_line)
    return not any(lo <= ln <= hi for ln in rebind_lines)


def _ip_suppressed(entry: dict, sink: dict) -> bool:
    tag = entry.get("sanitized")
    if not tag:
        return False
    if "*" in tag:
        return True
    context = sink.get("context")
    return context is not None and context in tag


def _intra_hit(entry: dict, item: dict, sink: dict, ctx: dict, reg: str) -> dict:
    return {"src_line": entry["line"], "src_method": entry["method"],
            "sink_line": ctx["base_ln"] + item["line"], "sink": sink["name"],
            "reg": reg, "src_owner": entry.get("owner"),
            "sink_owner": sink["owner"],
            "source_match": _match_info(entry["matcher"]),
            "sink_match": _match_info(sink),
            "path": list(entry.get("path") or [reg]),
            "src_file": entry.get("file") or ctx["file"],
            "sink_file": ctx["file"], "via": tuple(entry.get("via") or ())}


def _ip_sink_args(item: dict, sink: dict, state: dict, ctx: dict,
                  hits: list) -> None:
    """Sink-argument handling for interop modes.

    find mode: emit hits for tainted arguments (sanitized entries are
    suppressed and counted as passages). summary mode: record
    parameter->sink relations instead of hits.
    """
    regs = item["registers"]
    indexes = sink["argument_indexes"]
    positions = (range(len(regs)) if indexes is None
                 else [i for i in indexes if 0 <= i < len(regs)])
    for pos in positions:
        reg = regs[pos]
        value = state.get(reg)
        if not (isinstance(value, tuple) and value):
            continue
        if ctx["mode"] == "summary":
            entry = value[0]
            if entry.get("kind") == "param":
                ctx["relations"].append({
                    "pos": entry["index"], "sink": sink["name"],
                    "sink_owner": sink["owner"], "sink_file": ctx["file"],
                    "sink_line": ctx["base_ln"] + item["line"],
                    "match": _match_info(sink),
                    "sink_context": sink.get("context"),
                    "via": tuple(entry.get("via") or ())})
            continue
        chosen = None
        for entry in value:
            if _ip_suppressed(entry, sink):
                hits.append({"event": "sanitizer_passage",
                             "file": ctx["file"],
                             "line": ctx["base_ln"] + item["line"],
                             "reg": reg, "extra_key": _entry_key(entry)})
                continue
            chosen = entry
            break
        if chosen is not None:
            hits.append(_intra_hit(chosen, item, sink, ctx, reg))


def _relation_hits(key: tuple, summary: dict, item: dict, state: dict,
                   ctx: dict, hits: list) -> None:
    """find mode: a resolved callee's relations become hits at its call."""
    sig = _call_sig(key)
    regs = item["registers"]
    for rel in summary["relations"]:
        pos = _operand_pos(item, key, rel["pos"])
        if pos is None:
            continue
        reg = regs[pos]
        value = state.get(reg)
        if not (isinstance(value, tuple) and value):
            continue
        chosen = None
        for entry in value:
            if _ip_suppressed(entry, {"context": rel.get("sink_context")}):
                hits.append({"event": "sanitizer_passage",
                             "file": ctx["file"],
                             "line": ctx["base_ln"] + item["line"],
                             "reg": reg, "extra_key": _entry_key(entry)})
                continue
            chosen = entry
            break
        if chosen is None:
            continue
        via = (sig,) + tuple(rel["via"]) + tuple(chosen.get("via") or ())
        hits.append({
            "src_line": chosen["line"], "src_method": chosen["method"],
            "sink_line": rel["sink_line"], "sink": rel["sink"],
            "reg": reg, "src_owner": chosen.get("owner"),
            "sink_owner": rel["sink_owner"],
            "source_match": _match_info(chosen["matcher"]),
            "sink_match": rel["match"],
            "path": list(chosen.get("path") or [reg]),
            "src_file": chosen.get("file") or ctx["file"],
            "sink_file": rel["sink_file"], "via": via})


def _propagate_relations(key: tuple, summary: dict, item: dict, state: dict,
                         ctx: dict) -> None:
    """summary mode: relay a callee's relations onto our own parameters."""
    for rel in summary["relations"]:
        pos = _operand_pos(item, key, rel["pos"])
        if pos is None:
            continue
        value = state.get(item["registers"][pos])
        if not (isinstance(value, tuple) and value):
            continue
        entry = value[0]
        if entry.get("kind") != "param":
            continue
        ctx["relations"].append({
            "pos": entry["index"], "sink": rel["sink"],
            "sink_owner": rel["sink_owner"], "sink_file": rel["sink_file"],
            "sink_line": rel["sink_line"], "match": rel["match"],
            "sink_context": rel.get("sink_context"),
            "via": (_call_sig(key),) + tuple(rel["via"])
            + tuple(entry.get("via") or ())})


def _resolve_pending(key: tuple, item: dict, state: dict, ctx: dict,
                     hits: list) -> dict:
    """Pending result of a call to a non-source, non-sanitizer callee."""
    summary = ctx["summaries"].get(key)
    if key in ctx["ambiguous"]:
        if ctx["mode"] == "summary":
            ctx["reasons"].add("ambiguous callee used")
        return {"kind": "unknown"}
    if ctx["target_key"] is not None and key == ctx["target_key"]:
        if ctx["mode"] == "summary":
            ctx["reasons"].add("recursive summary dependency")
        return {"kind": "unknown"}
    if summary is None:
        if key in ctx["defined"]:
            return {"kind": "unknown"}
        return {"kind": "unknown", "unresolved": True}
    if ctx["mode"] == "find":
        if summary["relations"]:
            _relation_hits(key, summary, item, state, ctx, hits)
    else:
        _propagate_relations(key, summary, item, state, ctx)
    if not summary["complete"]:
        if ctx["mode"] == "summary":
            ctx["reasons"].add("uses incomplete summary")
        return {"kind": "unknown"}
    entries: list = []
    unknown = bool(summary["ret_unknown"])
    for index in sorted(summary["ret_dep"]):
        pos = _operand_pos(item, key, index)
        if pos is None:
            unknown = True
            continue
        value = state.get(item["registers"][pos])
        if value is UNKNOWN:
            unknown = True
        elif isinstance(value, tuple) and value:
            entry = value[0]
            entries.append({**entry, "via": (_call_sig(key),)
                            + tuple(entry.get("via") or ())})
    for entry in summary["ret_entries"]:
        entries.append({**entry, "via": (_call_sig(key),)
                        + tuple(entry.get("via") or ())})
    if entries:
        return {"kind": "entries", "entries": _sorted_entries(entries)}
    if unknown:
        return {"kind": "unknown"}
    return {"kind": "clean"}


def _sanitizer_pending(key: tuple, item: dict, san: dict, state: dict,
                       ctx: dict) -> dict:
    """Result of a call matching a sanitizer matcher (find mode only).

    A sanitizer is trusted only when its in-tree body resolves to a complete
    summary; otherwise the result is UNKNOWN and counted as unverified.
    Positions explicitly listed in `argument_indexes` (receiver-inclusive)
    get the sanitizer's context tag; other derivations stay raw.
    """
    summary = ctx["summaries"].get(key)
    usable = (key not in ctx["ambiguous"]
              and key != ctx["target_key"]
              and summary is not None
              and summary["complete"]
              and not summary["ret_unknown"])
    if not usable:
        return {"kind": "unknown", "unverified": True}
    widths = _param_widths(key[2])
    indexes = san["argument_indexes"]
    tag = tuple(san["contexts"] or ("*",))
    entries: list = []
    unknown = False
    for index in sorted(summary["ret_dep"]):
        if widths is None or index >= len(widths):
            unknown = True
            continue
        pos = _operand_pos(item, key, index)
        if pos is None:
            unknown = True
            continue
        value = state.get(item["registers"][pos])
        if value is UNKNOWN:
            unknown = True
            continue
        if not (isinstance(value, tuple) and value):
            continue
        entry = value[0]
        if indexes is None or pos in indexes:
            entry = {**entry, "sanitized": tag}
        else:
            entry = dict(entry)
        entries.append(entry)
    entries.extend(summary["ret_entries"])
    if entries:
        return {"kind": "entries", "entries": _sorted_entries(entries)}
    if unknown:
        return {"kind": "unknown"}
    return {"kind": "clean"}


def _ip_transfer(block, items: list, in_state: dict, ctx: dict):
    """Transfer one block in interop mode; returns (out_state, hits/events).

    Mirrors the fast per-instruction semantics (source pairing, const/move
    kills, array reads unknown) and adds: call resolution through summaries,
    parameter-aware sinks, sanitizer tagging, and unresolved/unverified
    events (counted once thanks to the fixed-point hit dedupe).
    """
    state = dict(in_state)
    hits: list = []
    pending = None
    for ln in range(block.start_line, block.end_line + 1):
        item = items[ln]
        if item["status"] != SP.PARSED:
            continue
        opcode = item["opcode"]
        if opcode.startswith("invoke"):
            ref = item["ref"]
            owner, name, descriptor = ref["owner"], ref["name"], ref["descriptor"]
            key = (owner, name, descriptor)
            source = next((m for m in ctx["src"]
                           if _match_call(m, owner, name)), None)
            if source is not None:
                pending = {"kind": "src", "entry": {
                    "line": ctx["base_ln"] + item["line"], "method": name,
                    "owner": owner, "matcher": source, "kind": "src",
                    "file": ctx["file"], "via": (), "sanitized": None}}
                continue
            sink = next((m for m in ctx["sinks"]
                         if _match_call(m, owner, name)), None)
            if sink is not None:
                _ip_sink_args(item, sink, state, ctx, hits)
            sanitizer = None
            if ctx["mode"] == "find" and ctx["sans"]:
                sanitizer = next((m for m in ctx["sans"]
                                  if _match_call(m, owner, name)), None)
            if sanitizer is not None:
                pending = _sanitizer_pending(key, item, sanitizer, state, ctx)
            else:
                pending = _resolve_pending(key, item, state, ctx, hits)
            continue
        if opcode.startswith("move-result"):
            reg = item["registers"][0]
            dsts = _wide_pair(reg) if "wide" in opcode else [reg]
            if pending is None:
                for d in dsts:
                    state[d] = UNKNOWN
            elif pending["kind"] == "src":
                for d in dsts:
                    state[d] = ({**pending["entry"], "path": [d]},)
            elif pending["kind"] == "entries":
                for d in dsts:
                    state[d] = _sorted_entries(
                        {**e, "path": list(e.get("path") or []) + [d]}
                        for e in pending["entries"])
            elif pending["kind"] == "clean":
                for d in dsts:
                    state.pop(d, None)
            else:
                for d in dsts:
                    state[d] = UNKNOWN
                if pending.get("unresolved"):
                    if ctx["mode"] == "find":
                        hits.append({"event": "unresolved",
                                     "file": ctx["file"],
                                     "line": ctx["base_ln"] + item["line"],
                                     "reg": reg})
                    else:
                        ctx["reasons"].add("unresolved callee result used")
                if pending.get("unverified") and ctx["mode"] == "find":
                    hits.append({"event": "sanitizer_unverified",
                                 "file": ctx["file"],
                                 "line": ctx["base_ln"] + item["line"],
                                 "reg": reg})
            pending = None
            continue
        if opcode.startswith(("const", "new-instance", "new-array")):
            reg = item["registers"][0]
            for d in (_wide_pair(reg) if "wide" in opcode else [reg]):
                state.pop(d, None)
            continue
        if opcode.startswith("aget"):
            reg = item["registers"][0]
            for d in (_wide_pair(reg) if "wide" in opcode else [reg]):
                state[d] = UNKNOWN
            continue
        if opcode == "fill-array-data":
            state[item["registers"][0]] = UNKNOWN
            continue
        if opcode == "move-exception":
            state.pop(item["registers"][0], None)
            continue
        if opcode.startswith(("iget", "sget")):
            reg = item["registers"][0]
            for d in (_wide_pair(reg) if "wide" in opcode else [reg]):
                state[d] = UNKNOWN
            continue
        if opcode.startswith(("iput", "sput", "aput")):
            continue
        if opcode.startswith("filled-new-array"):
            pending = None
            continue
        if opcode.split("/")[0] in SP.PROPAGATE_OPS:
            regs = item["registers"]
            dst, srcs = regs[0], regs[1:]
            wide = "-long" in opcode or "-double" in opcode
            dsts = _wide_pair(dst) if wide else [dst]
            value = None
            unknown = False
            for s in srcs:
                for ss in (_wide_pair(s) if wide else [s]):
                    v = state.get(ss)
                    if isinstance(v, tuple) and v:
                        value = _sorted_entries(list(value or ()) + list(v))
                    elif v is UNKNOWN:
                        unknown = True
            for d in dsts:
                state.pop(d, None)
            if value is not None:
                for d in dsts:
                    state[d] = _sorted_entries(
                        {**e, "path": list(e.get("path") or []) + [d]}
                        for e in value)
            elif unknown:
                for d in dsts:
                    state[d] = UNKNOWN
            continue
        if opcode.startswith("move"):
            dst, src = item["registers"]
            dsts = _wide_pair(dst) if "wide" in opcode else [dst]
            srcs = _wide_pair(src) if "wide" in opcode else [src]
            value = None
            for s in srcs:
                v = state.get(s)
                if isinstance(v, tuple) and v:
                    value = v
                    break
            if value is None and any(state.get(s) is UNKNOWN for s in srcs):
                value = UNKNOWN
            for d in dsts:
                state.pop(d, None)
            if value is UNKNOWN:
                for d in dsts:
                    state[d] = UNKNOWN
            elif value is not None:
                for d in dsts:
                    state[d] = _sorted_entries(
                        {**e, "path": list(e.get("path") or []) + [d]}
                        for e in value)
    return state, hits


def _entry_sig(entry: dict) -> tuple:
    return (_entry_key(entry), tuple(entry.get("path") or ()))


def _summary_signature(summary: dict) -> tuple:
    return (bool(summary["complete"]), bool(summary["ret_unknown"]),
            tuple(sorted(summary["ret_dep"])),
            tuple(_entry_sig(e) for e in summary["ret_entries"]),
            tuple((r["pos"], r["sink"], r["sink_owner"], r["sink_file"],
                   r["sink_line"], r["via"]) for r in summary["relations"]))


def _merge_relations(relations: list) -> tuple:
    best: dict = {}
    for rel in relations:
        key = (rel["pos"], rel["sink"], rel["sink_owner"], rel["sink_file"],
               rel["sink_line"])
        via = tuple(rel["via"])
        old = best.get(key)
        if old is None or (len(via), via) < (len(old["via"]), old["via"]):
            best[key] = {**rel, "via": via}
    return tuple(best[k] for k in sorted(best)[:_RELATION_CAP])


def _build_summary(key: tuple, meta: dict, ctx_base: dict, summaries: dict,
                   defined: dict, ambiguous: set, cache: dict) -> dict:
    """One method's summary: ret deps, ret entries, param->sink relations."""
    file = meta["file"]
    content = cache.get(meta["path"], _MISSING)
    if content is _MISSING:
        content = _read_file(meta["path"])
        cache[meta["path"]] = content
    lines = None
    if content is not None:
        for base_ln, _decl, block in _iter_method_blocks(content):
            if base_ln == meta["base_ln"]:
                lines = block
                break
    if lines is None:
        return {"complete": False, "reasons": ("method body not found",),
                "ret_dep": frozenset(), "ret_entries": (), "relations": (),
                "ret_unknown": True}
    descriptor = key[2]
    is_static = _is_static_decl(meta["decl"])
    mapping, param_ok = _param_map(lines, is_static)
    items, cfg, coverage = _coverage(lines)
    reasons = set(_coverage_problems(coverage, param_ok))
    relations: list = []
    ctx = {"mode": "summary", "file": file, "base_ln": meta["base_ln"],
           "src": ctx_base["src"], "sinks": ctx_base["sinks"], "sans": (),
           "summaries": summaries, "ambiguous": ambiguous, "defined": defined,
           "target_key": key, "reasons": reasons, "relations": relations}
    out_states: dict = {}
    if cfg.blocks:
        _, capped = _fixed_point(
            cfg, items, ctx["src"], (),
            transfer=lambda b, its, st: _ip_transfer(b, its, st, ctx),
            entry_state=_seed_params(mapping, file, _call_sig(key)),
            out_result=out_states)
        if capped:
            reasons.add("fixed-point visit cap reached")
    ret_dep: set = set()
    ret_entries: list = []
    ret_unknown = False
    if not descriptor.endswith(")V"):
        found_return = False
        for block in cfg.blocks:
            if block.terminator != "return":
                continue
            m = _RETURN_RE.match((block.lines[-1] if block.lines else "") or "")
            if not m:
                continue
            found_return = True
            out = out_states.get(block.block_id)
            if out is None:
                ret_unknown = True
                continue
            value = out.get(m.group(1))
            if value is UNKNOWN:
                ret_unknown = True
            elif isinstance(value, tuple) and value:
                for entry in value:
                    if entry.get("kind") == "param":
                        ret_dep.add(entry["index"])
                    else:
                        ret_entries.append(entry)
        if not found_return:
            ret_unknown = True
    return {"complete": not reasons, "reasons": tuple(sorted(reasons)),
            "ret_dep": frozenset(ret_dep),
            "ret_entries": _merge_entries([ret_entries]),
            "relations": _merge_relations(relations),
            "ret_unknown": ret_unknown}


def _build_summaries(targets: list, defined: dict, ambiguous: set,
                     ctx_base: dict, cache: dict) -> dict:
    """Bounded Gauss-Seidel fix point over referenced method summaries."""
    summaries: dict = {}
    changed: list = []
    for _pass in range(_SUMMARY_PASS_CAP):
        cache.clear()
        changed = []
        for key in targets:
            summary = _build_summary(key, defined[key], ctx_base, summaries,
                                     defined, ambiguous, cache)
            old = summaries.get(key)
            if (old is None
                    or _summary_signature(old) != _summary_signature(summary)):
                changed.append(key)
            summaries[key] = summary
        if not changed:
            break
    if changed:
        for key in changed:
            current = summaries[key]
            summaries[key] = {
                **current, "complete": False,
                "reasons": tuple(sorted(set(current["reasons"])
                                        | {"summary did not converge"}))}
    return summaries


def _scan_interprocedural(base: str, decoded: str, rule, src_matchers: list,
                          sink_matchers: list, san_matchers: list, cap: int,
                          include_vendor: bool, skip_dirs: set,
                          totals: dict) -> list:
    """TF-02 Stage 4 scan for one opt-in rule; findings + totals in place."""
    out: list = []
    suppress_relaunch = bool(
        (getattr(rule, "params", None) or {}).get("suppress_self_relaunch"))
    paths = _iter_smali_files(base, include_vendor, skip_dirs)
    metas: list = []
    defined: dict = {}
    ambiguous: set = set()
    referenced: set = set()
    no_class_seen: set = set()
    for path in paths:
        content, truncated = _read_capped(path)
        if content is None:
            continue
        totals["files_scanned"] += 1
        if truncated:
            totals["files_truncated"] += 1
        rel = os.path.relpath(path, decoded)
        owner = _class_of(content)
        if owner is None:
            if path not in no_class_seen:
                no_class_seen.add(path)
                totals["files_no_class"] += 1
            continue
        for base_ln, decl, lines in _iter_method_blocks(content):
            parsed = SP.method_declaration(decl)
            if parsed is None:
                totals["methods_skipped"] += 1
                metas.append({"path": path, "file": rel, "owner": owner,
                              "base_ln": base_ln, "decl": decl, "key": None})
                continue
            name, descriptor = parsed
            key = (owner, name, descriptor)
            totals["methods_scanned"] += 1
            meta = {"path": path, "file": rel, "owner": owner,
                    "base_ln": base_ln, "decl": decl, "key": key,
                    "name": name, "descriptor": descriptor,
                    "sig": _call_sig(key)}
            metas.append(meta)
            if key in defined:
                ambiguous.add(key)
            else:
                defined[key] = meta
            for item in SP.parse_lines(lines):
                ref = item["ref"]
                if (item["status"] == SP.PARSED and ref is not None
                        and item["opcode"].startswith("invoke")):
                    referenced.add((ref["owner"], ref["name"],
                                    ref["descriptor"]))
    targets = sorted(
        (k for k in defined if k in referenced and k not in ambiguous),
        key=lambda k: (defined[k]["file"], defined[k]["base_ln"]))
    cache: dict = {}
    summaries = _build_summaries(
        targets, defined, ambiguous,
        {"src": src_matchers, "sinks": sink_matchers}, cache)
    totals["summaries_built"] += len(summaries)
    totals["summaries_incomplete"] += sum(
        1 for s in summaries.values() if not s["complete"])
    totals["ambiguous_methods"] += len(ambiguous)
    hits_so_far = 0
    start = len(out)
    for path in paths:
        if hits_so_far >= cap:
            break
        content = _read_file(path)
        if content is None:
            continue
        rel = os.path.relpath(path, decoded)
        owner = _class_of(content)
        if owner is None:
            if path not in no_class_seen:
                no_class_seen.add(path)
                totals["files_no_class"] += 1
            continue
        for base_ln, decl, lines in _iter_method_blocks(content):
            if hits_so_far >= cap:
                break
            parsed = SP.method_declaration(decl)
            if parsed is None:
                continue
            name, descriptor = parsed
            items, cfg, coverage = _coverage(lines)
            totals["unsupported_instructions"] += coverage["unsupported_instructions"]
            totals["malformed_instructions"] += coverage["malformed_instructions"]
            totals["missing_labels"] += coverage["missing_labels"]
            totals["unresolved_switches"] += coverage["unresolved_switches"]
            hits: list = []
            capped = False
            if cfg.blocks:
                ctx = {"mode": "find", "file": rel, "base_ln": base_ln,
                       "src": src_matchers, "sinks": sink_matchers,
                       "sans": san_matchers, "summaries": summaries,
                       "ambiguous": ambiguous, "defined": defined,
                       "target_key": (owner, name, descriptor),
                       "reasons": set()}
                hits, capped = _fixed_point(
                    cfg, items, src_matchers, (),
                    transfer=lambda b, its, st: _ip_transfer(b, its, st, ctx))
            if capped:
                totals["cfg_capped_any"] = True
            coverage["capped"] = 1 if capped else 0
            for ev in hits:
                if ev.get("event") == "unresolved":
                    totals["unresolved_calls"] += 1
                elif ev.get("event") == "sanitizer_unverified":
                    totals["sanitizers_unverified"] += 1
                elif ev.get("event") == "sanitizer_passage":
                    totals["sanitizer_passages"] += 1
            pieces = _coverage_pieces(coverage)
            gap_text = ("; " + "; ".join(pieces)) if pieces else ""
            sig = _call_sig((owner, name, descriptor))
            rebind = _rebind_lines(items, base_ln)
            for hit in hits:
                if hit.get("event"):
                    continue
                self_relaunch = _self_relaunch(
                    hit.get("source_match"), hit.get("sink_match"),
                    hit.get("src_line"), hit.get("sink_line"), rebind)
                if self_relaunch:
                    totals["self_relaunch"] += 1
                    if suppress_relaunch:
                        totals["self_relaunch_suppressed"] += 1
                        continue
                via = tuple(hit.get("via") or ())
                cross = bool(via) or (hit.get("src_file")
                                      != hit.get("sink_file"))
                scope = analysis_scope(interprocedural=True)
                scope.update({
                    "status": "partial", "truncated": False,
                    "reason": ("interprocedural summary propagation;"
                               " see limitations" if cross else
                               "intra-method CFG fixed-point scan;"
                               " see limitations") + gap_text})
                if self_relaunch:
                    scope["classification"] = "self-relaunch"
                evidence = (f"{rel}:{sig}: tainted {hit['reg']} "
                            f"from {hit['src_method']} reaches {hit['sink']}")
                if via:
                    evidence += f" via {' -> '.join(via)}"
                out.append(R.finding(
                    rule, file=rel, evidence=evidence,
                    extra={"method": sig, "sink": hit["sink"],
                           "reg": hit["reg"],
                           "src_method": hit["src_method"],
                           "src_line": hit["src_line"],
                           "sink_line": hit["sink_line"],
                           "register_path": hit["path"],
                           "src_owner": hit["src_owner"],
                           "sink_owner": hit["sink_owner"],
                           "source_match": hit["source_match"],
                           "sink_match": hit["sink_match"],
                           "src_file": hit["src_file"],
                           "sink_file": hit["sink_file"],
                           "cross_method": cross,
                           "via": list(via),
                           "analysis": scope,
                           **({"self_relaunch": True} if self_relaunch else {})}))
                hits_so_far += 1
                totals["hits"] += 1
                if hits_so_far >= cap:
                    break
    if hits_so_far >= cap:
        totals["truncated_any"] = True
        for i in range(start, len(out)):
            det = out[i].setdefault("detail", {})
            det["truncated"] = True
            det["limit"] = cap
            analysis = det.get("analysis")
            if isinstance(analysis, dict):
                analysis["truncated"] = True
        out[-1]["evidence"] += f" [truncated at {cap} hits]"
    return out


def scan(decoded: str, rules: list, limit_default: int = 15,
         stats: dict | None = None) -> list[dict]:
    """Scan methods for source->sink flows. Additive `stats` (optional).

    `stats` receives `methods_scanned`, `files_scanned`, `files_truncated`,
    `hits`, `truncated_any`, and coverage counters (`unsupported_instructions`,
    `malformed_instructions`, `methods_skipped`, `missing_labels`,
    `unresolved_switches`, `cfg_capped_any`, all zero when measured and
    clean). Coverage counters accumulate per rule scan; a tree scanned by N
    taint rules reports each encounter N times. Callers can distinguish a
    true negative (methods ran, nothing found) from unscanned input (no
    methods ran) and from unmeasured coverage (counters absent). Findings
    carry an `analysis` descriptor marking them `candidate`, never verified.
    """
    out: list[dict] = []
    totals = {"methods_scanned": 0, "files_scanned": 0, "files_truncated": 0,
              "hits": 0,
              "files_no_class": 0,
              "truncated_any": False, "unsupported_instructions": 0,
              "malformed_instructions": 0, "methods_skipped": 0,
              "missing_labels": 0, "unresolved_switches": 0,
              "cfg_capped_any": False,
              "unresolved_calls": 0, "sanitizers_unverified": 0,
              "summaries_incomplete": 0, "ambiguous_methods": 0,
              "sanitizer_passages": 0, "summaries_built": 0,
              "self_relaunch": 0, "self_relaunch_suppressed": 0}
    if not decoded or not os.path.isdir(decoded):
        if stats is not None:
            stats.update(totals)
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
            src_matchers = compile_matchers(sources, "sources")
            sink_matchers = compile_matchers(sinks, "sinks")
            san_matchers = compile_matchers(r.params.get("sanitizers") or [],
                                            "sanitizers")
        except (re.error, ValueError, TypeError) as e:
            out.append(R.finding(r, evidence=f"bad taint matcher: {e}"))
            continue
        suppress_relaunch = bool(r.params.get("suppress_self_relaunch"))
        base = os.path.join(decoded, r.params.get("root", "."))
        if not os.path.isdir(base):
            continue
        if r.params.get("interprocedural", False) is True:
            out.extend(_scan_interprocedural(
                base, decoded, r, src_matchers, sink_matchers, san_matchers,
                cap, include_vendor, skip_dirs, totals))
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
                content, truncated = _read_capped(p)
                if content is None:
                    continue
                totals["files_scanned"] += 1
                if truncated:
                    totals["files_truncated"] += 1
                block: list[str] = []
                in_method = False
                sig = ""
                base_ln = 0

                def emit() -> bool:
                    """Scan the current block; True when the cap is hit."""
                    nonlocal hits
                    mcounters: dict = {}
                    found = _analyze_method(block, src_matchers,
                                            sink_matchers, mcounters)
                    totals["unsupported_instructions"] += \
                        mcounters["unsupported_instructions"]
                    totals["malformed_instructions"] += \
                        mcounters["malformed_instructions"]
                    totals["missing_labels"] += mcounters["missing_labels"]
                    totals["unresolved_switches"] += \
                        mcounters["unresolved_switches"]
                    if mcounters["capped"]:
                        totals["cfg_capped_any"] = True
                    pieces = _coverage_pieces(mcounters)
                    gap_text = ("; " + "; ".join(pieces)) if pieces else ""
                    rebind = _rebind_lines(SP.parse_lines(block), base_ln)
                    for h in found:
                        relp = os.path.relpath(p, decoded)
                        self_relaunch = _self_relaunch(
                            h.get("source_match"), h.get("sink_match"),
                            base_ln + h["src_line"],
                            base_ln + h["sink_line"], rebind)
                        if self_relaunch:
                            totals["self_relaunch"] += 1
                            if suppress_relaunch:
                                totals["self_relaunch_suppressed"] += 1
                                continue
                        scope = analysis_scope()
                        scope.update({"status": "partial",
                                      "truncated": False,
                                      "reason": ("intra-method CFG fixed-point "
                                                 "scan; see limitations"
                                                 + gap_text)})
                        if self_relaunch:
                            scope["classification"] = "self-relaunch"
                        out.append(R.finding(
                            r, file=relp,
                            evidence=(f"{relp}:{sig}: tainted {h['reg']} "
                                      f"from {h['src_method']} reaches "
                                      f"{h['sink']}"),
                            extra={"method": sig, "sink": h["sink"],
                                   "reg": h["reg"],
                                   "src_method": h["src_method"],
                                   "src_line": base_ln + h["src_line"],
                                   "sink_line": base_ln + h["sink_line"],
                                   "register_path": h["path"],
                                   "src_owner": h["src_owner"],
                                   "sink_owner": h["sink_owner"],
                                   "source_match": h["source_match"],
                                   "sink_match": h["sink_match"],
                                   "analysis": scope,
                                   **({"self_relaunch": True}
                                      if self_relaunch else {})}))
                        hits += 1
                        totals["hits"] += 1
                        if hits >= cap:
                            return True
                    return False

                for ln, raw in enumerate(content.splitlines()):
                    if _METHOD_RE.match(raw):
                        if SP.method_declaration(raw) is None:
                            # Unparseable .method declaration: skip the block
                            # instead of scanning it under a bogus signature.
                            totals["methods_skipped"] += 1
                            in_method = False
                            block = []
                            continue
                        in_method = True
                        block = [raw]
                        sig = raw.strip()[:120]
                        base_ln = ln
                        totals["methods_scanned"] += 1
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
            totals["truncated_any"] = True
            for i in range(start, len(out)):
                det = out[i].setdefault("detail", {})
                det["truncated"] = True
                det["limit"] = cap
                analysis = det.get("analysis")
                if isinstance(analysis, dict):
                    analysis["truncated"] = True
            out[-1]["evidence"] += f" [truncated at {cap} hits]"
    if stats is not None:
        stats.update(totals)
    return out
