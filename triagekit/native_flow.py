"""NF-01: native call-site and input/output provenance evidence graph
(plan §15).

First milestone: evidence collection, not automatic decompilation and not
a claim that a routine has been understood. Every node and edge carries an
explicit confidence (``confirmed``/``candidate``/``unresolved``); unknown
targets and unproven boundaries are reported, never invented.

Static analysis only: disassembly text is parsed as data, nothing is
executed, and high-entropy or buffer-like data is never classified as
encryption or DEX here.
"""

from __future__ import annotations

import re

GRAPH_LIMITATIONS = (
    "evidence collection only; not a complete data-flow analysis",
    "function boundaries come from dynamic symbols and call-site addresses "
    "only",
    "a byte buffer is not necessarily a DEX file; buffer identity is not "
    "inferred here",
    "high-entropy outputs are not classified as encryption",
    "functions near JNI_OnLoad are not assumed to be registration callbacks",
)

_ABIS = {
    "x86_64": {
        "abi": "x86_64-sysv",
        "argument_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        "return_register": "rax",
    },
    "aarch64": {
        "abi": "aarch64-aapcs64",
        "argument_registers": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        "return_register": "x0",
    },
    "armeabi-v7a": {
        "abi": "armeabi-v7a-aapcs",
        "argument_registers": ["r0", "r1", "r2", "r3"],
        "return_register": "r0",
    },
}

_CALL_PATTERNS = {
    "x86_64": (
        re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+callq?\s+"
                   r"(?:0x)?([0-9a-f]+)\s+<([^>]+)>"),
        re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+callq?\s+\*"),
    ),
    "aarch64": (
        re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+bl\s+"
                   r"(?:0x)?([0-9a-f]+)\s+<([^>]+)>"),
        re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+blr\s+(\w+)"),
    ),
    "armeabi-v7a": (
        re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(?:bl|blx)\s+"
                   r"(?:0x)?([0-9a-f]+)\s+<([^>]+)>"),
        re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+blx\s+(\w+)"),
    ),
}

_ARCH_ALIASES = {
    "x86_64": "x86_64",
    "x86-64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "armeabi-v7a": "armeabi-v7a",
    "arm": "armeabi-v7a",
    "armv7": "armeabi-v7a",
}

_MAX_PLAUSIBLE_FUNCTION_SIZE = 16 * 1024 * 1024


def _normalize_arch(arch: str) -> str:
    name = (arch or "").strip().lower()
    return _ARCH_ALIASES.get(name, name)


def abi_summary(arch: str) -> dict:
    """Argument/return registers per ABI convention (not observed values)."""
    entry = _ABIS.get(_normalize_arch(arch))
    if entry is None:
        return {"abi": arch or "unknown", "argument_registers": [],
                "return_register": None, "supported": False}
    return {"abi": entry["abi"],
            "argument_registers": list(entry["argument_registers"]),
            "return_register": entry["return_register"],
            "supported": True}


def parse_call_sites(disassembly_text: str, *, function_id: str,
                     arch: str = "x86_64") -> list[dict]:
    """Extract direct and indirect call sites from objdump-style text."""
    patterns = _CALL_PATTERNS.get(_normalize_arch(arch))
    if patterns is None:
        return []
    direct_re, indirect_re = patterns
    sites: list[dict] = []
    for line in disassembly_text.splitlines():
        match = direct_re.match(line)
        if match is not None:
            sites.append({
                "function_id": function_id,
                "site": int(match.group(1), 16),
                "kind": "direct",
                "target_address": int(match.group(2), 16),
                "target_symbol": match.group(3),
                "register": None,
            })
            continue
        match = indirect_re.match(line)
        if match is not None:
            groups = match.groups()
            register = groups[1] if len(groups) > 1 else None
            sites.append({
                "function_id": function_id,
                "site": int(groups[0], 16),
                "kind": "indirect",
                "target_address": None,
                "target_symbol": None,
                "register": register,
            })
    sites.sort(key=lambda s: s["site"])
    return sites


def build(*, library: str, library_sha256: str = "", jni_records=None,
          symbols=None, disassembly=None, arch: str = "x86_64",
          indirect_candidates=None) -> dict:
    """Assemble the evidence graph for one native library.

    ``disassembly`` maps a function node id (or symbol name) to
    objdump-style text for that function.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    unknowns: list[dict] = []
    node_ids: set[str] = set()
    edge_keys: set[tuple] = set()

    arch = _normalize_arch(arch)
    if arch not in _ABIS:
        unknowns.append({
            "type": "unsupported-arch",
            "arch": arch,
            "reason": "architecture '%s' has no call-site patterns; an empty "
                      "graph is not evidence of absence" % arch,
        })

    def add_node(node: dict) -> None:
        if node["id"] not in node_ids:
            node_ids.add(node["id"])
            nodes.append(node)

    def add_edge(edge: dict) -> None:
        key = (edge["from"], edge["to"], edge["kind"], edge["confidence"],
               edge.get("site"))
        if key not in edge_keys:
            edge_keys.add(key)
            edges.append(edge)

    defined = {}
    for sym in symbols or []:
        if sym.get("defined"):
            defined[sym["name"]] = sym

    fn_by_va: dict[int, str] = {}
    fn_by_symbol: dict[str, str] = {}

    for rec in jni_records or []:
        java_method = rec["java_method"]
        jni_id = "jni:" + java_method
        mapping_confidence = rec["confidence"]
        if mapping_confidence in ("confirmed_symbol_match",
                                  "supported_registration_match"):
            node_confidence = "supported"
        elif mapping_confidence == "candidate_string_or_table_match":
            node_confidence = "candidate"
        else:
            node_confidence = "unresolved"
        add_node({
            "id": jni_id,
            "kind": "jni-method",
            "confidence": node_confidence,
            "java_method": java_method,
            "native_library": rec.get("native_library", library),
            "limitations": list(rec.get("limitations") or []),
        })
        symbol = rec.get("native_symbol")
        va = rec.get("elf_virtual_address")
        if node_confidence == "supported" and symbol:
            fn_id = "elf:%s:0x%x" % (library, va)
            symrec = defined.get(symbol) or {}
            size = symrec.get("size") or 0
            size_implausible = size > _MAX_PLAUSIBLE_FUNCTION_SIZE
            end = (va + size if 0 < size <= _MAX_PLAUSIBLE_FUNCTION_SIZE
                   else None)
            add_node({
                "id": fn_id,
                "kind": "native-function",
                "confidence": "confirmed",
                "start": va,
                "end": end,
                "symbol": symbol,
                "boundary_evidence": (["elf-dynamic-symbol"]
                                      + (["symbol-size"] if end else [])),
                "source_artifact_sha256": library_sha256,
            })
            fn_by_va.setdefault(va, fn_id)
            fn_by_symbol.setdefault(symbol, fn_id)
            if end is None:
                unknowns.append({
                    "type": "function-end",
                    "function": fn_id,
                    "reason": (
                        "dynamic symbol size implausibly large (0x%x bytes); "
                        "end not claimed" % size
                        if size_implausible else
                        "dynamic symbol has no size; end unknown"),
                })
            add_edge({
                "from": jni_id,
                "to": fn_id,
                "kind": "calls",
                "confidence": "confirmed",
                "evidence": [{"type": "jni-mapping",
                              "mapping_confidence": mapping_confidence}],
            })
        elif node_confidence == "candidate":
            unknowns.append({
                "type": "unresolved-jni-mapping",
                "java_method": java_method,
                "reason": "JNI mapping is a candidate; no confirmed function "
                          "target",
            })
        else:
            unknowns.append({
                "type": "unresolved-jni-mapping",
                "java_method": java_method,
                "reason": "no exported symbol or registration evidence",
            })

    candidates = indirect_candidates or {}
    for key, text in (disassembly or {}).items():
        fn_id = fn_by_symbol.get(key, key)
        if fn_id not in node_ids:
            add_node({
                "id": fn_id,
                "kind": "native-function",
                "confidence": "candidate",
                "start": None,
                "end": None,
                "symbol": key,
                "boundary_evidence": ["disassembly-input"],
                "source_artifact_sha256": library_sha256,
            })
        for site in parse_call_sites(text, function_id=fn_id, arch=arch):
            if site["kind"] == "direct":
                target_id = fn_by_va.get(site["target_address"])
                if target_id is None:
                    target_id = "elf:%s:0x%x" % (library,
                                                 site["target_address"])
                    add_node({
                        "id": target_id,
                        "kind": "native-function",
                        "confidence": "candidate",
                        "start": site["target_address"],
                        "end": None,
                        "symbol": site["target_symbol"],
                        "boundary_evidence": ["call-site"],
                        "source_artifact_sha256": library_sha256,
                    })
                add_edge({
                    "from": fn_id,
                    "to": target_id,
                    "kind": "calls",
                    "confidence": "confirmed",
                    "site": site["site"],
                    "evidence": [{"type": "direct-call-instruction",
                                  "site": site["site"]}],
                })
            else:
                site_candidates = candidates.get(site["site"])
                if site_candidates:
                    for candidate in site_candidates:
                        target_id = "elf:%s:0x%x" % (library,
                                                     candidate["va"])
                        add_node({
                            "id": target_id,
                            "kind": "native-function",
                            "confidence": "candidate",
                            "start": candidate["va"],
                            "end": None,
                            "symbol": candidate.get("symbol"),
                            "boundary_evidence": ["call-site"],
                            "source_artifact_sha256": library_sha256,
                        })
                        add_edge({
                            "from": fn_id,
                            "to": target_id,
                            "kind": "calls",
                            "confidence": "candidate",
                            "site": site["site"],
                            "evidence": [{"type": "indirect-call-candidate",
                                          "site": site["site"]}],
                        })
                    if len(site_candidates) > 1:
                        unknowns.append({
                            "type": "multiple-indirect-targets",
                            "function": fn_id,
                            "site": site["site"],
                            "reason": "indirect call has multiple possible "
                                      "targets; none confirmed",
                        })
                    else:
                        unknowns.append({
                            "type": "single-indirect-target",
                            "function": fn_id,
                            "site": site["site"],
                            "reason": "indirect call resolved to one "
                                      "candidate target; not confirmed",
                        })
                else:
                    unknown_id = "unknown:%s:0x%x" % (library, site["site"])
                    add_node({
                        "id": unknown_id,
                        "kind": "unknown",
                        "confidence": "unresolved",
                    })
                    add_edge({
                        "from": fn_id,
                        "to": unknown_id,
                        "kind": "calls",
                        "confidence": "unresolved",
                        "site": site["site"],
                        "evidence": [{"type": "indirect-call-instruction",
                                      "site": site["site"]}],
                    })
                    unknowns.append({
                        "type": "indirect-call",
                        "function": fn_id,
                        "site": site["site"],
                        "reason": "target register/offset not statically "
                                  "resolved",
                    })

    return {
        "library": library,
        "library_sha256": library_sha256,
        "arch": arch,
        "abi": abi_summary(arch),
        "nodes": nodes,
        "edges": edges,
        "unknowns": unknowns,
        "limitations": list(GRAPH_LIMITATIONS),
    }
