"""JNI-01: Java/native correlation (plan §13).

Links Smali native declarations to candidate native implementations via
conventional symbol mangling, dynamic-registration indicators, and
caller-supplied structural table evidence.

Static analysis only: this module never executes a native library, never
invokes external ELF tools (capability presence is reported, not used),
and never treats matching strings alone as proof of function identity.
"""

from __future__ import annotations

import shutil

CONFIDENCE_LEVELS = (
    "confirmed_symbol_match",
    "supported_registration_match",
    "candidate_string_or_table_match",
    "unresolved",
)

MAPPING_TYPES = ("conventional-symbol", "dynamic-registration-candidate",
                 "unresolved")

_ELIGIBLE_TOOLS = ("readelf", "llvm-readelf")


def _utf16_units(code_point: int) -> list[int]:
    if code_point <= 0xFFFF:
        return [code_point]
    cp = code_point - 0x10000
    return [0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF)]


def _mangle_text(text: str) -> str:
    """JNI name escaping: alphanumerics kept, / -> _, _ -> _1, ; -> _2,
    [ -> _3, every other character -> _0XXXX (UTF-16 code units)."""
    out: list[str] = []
    for ch in text:
        if ch.isascii() and ch.isalnum():
            out.append(ch)
        elif ch == "/":
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        else:
            for unit in _utf16_units(ord(ch)):
                out.append("_0%04x" % unit)
    return "".join(out)


def _mangle_class(descriptor: str) -> str:
    if descriptor.startswith("["):
        return _mangle_text(descriptor)
    d = descriptor
    if d.startswith("L") and d.endswith(";"):
        d = d[1:-1]
    return _mangle_text(d)


def _split_signature(signature: str) -> tuple[str, str]:
    close = signature.find(")")
    if not signature.startswith("(") or close < 0:
        return "", ""
    return signature[1:close], signature[close + 1:]


def _split_params(args: str) -> list[str]:
    types: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "[":
            j = i
            while j < len(args) and args[j] == "[":
                j += 1
            if j < len(args) and args[j] == "L":
                k = args.find(";", j)
                if k < 0:
                    # malformed descriptor: consume the rest, never raise
                    types.append(args[i:])
                    break
                types.append(args[i:k + 1])
                i = k + 1
            else:
                types.append(args[i:j + 1])
                i = j + 1
        elif args[i] == "L":
            k = args.find(";", i)
            if k < 0:
                # malformed descriptor: consume the rest, never raise
                types.append(args[i:])
                break
            types.append(args[i:k + 1])
            i = k + 1
        else:
            types.append(args[i])
            i += 1
    return types


def jni_symbol_candidates(class_descriptor: str, method_name: str,
                          signature: str | None = None) -> list[str]:
    """Conventional JNI names: short name first, then overload long-name
    variants (arguments, then arguments plus return type)."""
    short = "Java_%s_%s" % (_mangle_class(class_descriptor),
                            _mangle_text(method_name))
    candidates = [short]
    if signature:
        args, ret = _split_signature(signature)
        long_args = short + "__" + "".join(
            _mangle_text(t) for t in _split_params(args))
        candidates.append(long_args)
        if ret:
            candidates.append(long_args + _mangle_text(ret))
    return list(dict.fromkeys(candidates))


def parse_native_declarations(smali_text: str,
                              class_descriptor: str | None = None,
                              *, file: str = "") -> list[dict]:
    """Collect `.method ... native name(sig)` declarations from Smali text."""
    decls: list[dict] = []
    detected_class = class_descriptor or ""
    for line_number, raw in enumerate(smali_text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith(".class "):
            if class_descriptor is None:
                tokens = line.split()
                if tokens:
                    detected_class = tokens[-1]
            continue
        if not line.startswith(".method "):
            continue
        body = line.split()[1:]
        if "native" not in body:
            continue
        name_sig = body[-1]
        if "(" not in name_sig:
            continue
        name, _, rest = name_sig.partition("(")
        signature = "(" + rest
        cls = class_descriptor or detected_class
        decls.append({
            "java_method": f"{cls}->{name}{signature}",
            "class_descriptor": cls,
            "method_name": name,
            "signature": signature,
            "flags": [t for t in body[:-1] if t != "native"],
            "file": file,
            "line": line_number,
            "evidence": {"type": "smali-native-declaration",
                         "file": file, "line": line_number},
        })
    return decls


def _find_table_entry(table_evidence, decl) -> dict | None:
    for entry in table_evidence or []:
        if entry.get("name") != decl["method_name"]:
            continue
        entry_sig = entry.get("signature")
        if entry_sig is not None and entry_sig != decl["signature"]:
            continue
        return entry
    return None


def correlate(declarations: list[dict], *, library: str,
              library_sha256: str = "", symbols=None, strings=None,
              table_evidence=None, symbol_errors=None) -> list[dict]:
    """Correlate declarations against one library's static evidence."""
    symbol_list = list(symbols or [])
    sym_errors = [str(e) for e in (symbol_errors or [])]
    defined = {s["name"]: s for s in symbol_list if s.get("defined")}
    known_strings = set(strings or [])
    has_onload = "JNI_OnLoad" in defined
    has_registers = "RegisterNatives" in known_strings

    records: list[dict] = []
    for decl in declarations:
        evidence = [dict(decl["evidence"])]
        limitations: list[str] = []
        native_symbol = None
        elf_va = 0

        matched = None
        for candidate in jni_symbol_candidates(
                decl["class_descriptor"], decl["method_name"],
                decl["signature"]):
            if candidate in defined:
                matched = defined[candidate]
                break

        if matched is not None:
            mapping_type = "conventional-symbol"
            confidence = "confirmed_symbol_match"
            native_symbol = matched["name"]
            elf_va = matched["value"]
            evidence.append({"type": "elf-dynamic-symbol",
                             "name": matched["name"],
                             "value": matched["value"],
                             "bind": matched.get("bind", "unknown")})
        else:
            table_entry = _find_table_entry(table_evidence, decl)
            table_function = (table_entry or {}).get("function")
            if table_function and table_function in defined and \
                    (table_entry or {}).get("signature") == decl["signature"]:
                mapping_type = "dynamic-registration-candidate"
                confidence = "supported_registration_match"
                native_symbol = table_function
                elf_va = defined[table_function]["value"]
                evidence.append({
                    "type": "register-natives-table-entry",
                    "name": table_entry.get("name"),
                    "signature": table_entry.get("signature"),
                    "function": table_function,
                    "file_offset": table_entry.get("file_offset"),
                })
                evidence.append({"type": "elf-dynamic-symbol",
                                 "name": table_function,
                                 "value": defined[table_function]["value"],
                                 "bind": defined[table_function].get(
                                     "bind", "unknown")})
            elif table_function and table_function in defined:
                # defined pointer but the entry carries no signature: one
                # function pointer must not be promoted to a supported match
                # for several distinct overloads.
                mapping_type = "dynamic-registration-candidate"
                confidence = "candidate_string_or_table_match"
                native_symbol = table_function
                elf_va = defined[table_function]["value"]
                evidence.append({
                    "type": "register-natives-table-entry",
                    "name": table_entry.get("name"),
                    "signature": table_entry.get("signature"),
                    "function": table_function,
                    "file_offset": table_entry.get("file_offset"),
                })
                evidence.append({"type": "elf-dynamic-symbol",
                                 "name": table_function,
                                 "value": defined[table_function]["value"],
                                 "bind": defined[table_function].get(
                                     "bind", "unknown")})
                limitations.append(
                    "registration table entry has no signature; it cannot be "
                    "bound to this specific overload (one pointer may serve "
                    "several methods)")
            elif table_entry is not None and table_function:
                mapping_type = "dynamic-registration-candidate"
                confidence = "candidate_string_or_table_match"
                evidence.append({"type": "register-natives-table-entry",
                                 "name": table_entry.get("name"),
                                 "signature": table_entry.get("signature"),
                                 "function": table_function,
                                 "file_offset": table_entry.get("file_offset")})
                limitations.append(
                    "registration table entry present but function pointer "
                    "not validated against defined dynamic symbols")
            elif has_onload or has_registers or \
                    decl["method_name"] in known_strings:
                mapping_type = "dynamic-registration-candidate"
                confidence = "candidate_string_or_table_match"
                if has_onload:
                    evidence.append({"type": "jni-onload-symbol",
                                     "name": "JNI_OnLoad"})
                    limitations.append(
                        "JNI_OnLoad present; registration table layout "
                        "unverified")
                if has_registers:
                    evidence.append({"type": "register-natives-string"})
                if decl["method_name"] in known_strings:
                    evidence.append({"type": "native-method-name-string",
                                     "value": decl["method_name"]})
                    limitations.append(
                        "matching strings alone are not proof of function "
                        "identity")
                limitations.append(
                    "function pointer not independently resolved")
            else:
                mapping_type = "unresolved"
                confidence = "unresolved"
                if sym_errors:
                    limitations.append(
                        f"{len(sym_errors)} ELF symbol parse error(s): "
                        "correlation ran against an incomplete symbol table")
                    limitations.append(
                        "no matching exported symbol in a partially "
                        "unparseable symbol table")
                else:
                    limitations.append(
                        "no matching exported symbol or registration evidence")

        records.append({
            "java_method": decl["java_method"],
            "native_library": library,
            "library_sha256": library_sha256,
            "mapping_type": mapping_type,
            "native_symbol": native_symbol,
            "elf_virtual_address": elf_va,
            "evidence": evidence,
            "confidence": confidence,
            "limitations": limitations,
        })
    return records


def capabilities() -> dict:
    """Report presence of optional external ELF tools; never executes."""
    caps = {tool: shutil.which(tool) is not None for tool in _ELIGIBLE_TOOLS}
    caps["note"] = ("optional external ELF tools are reported only; "
                    "triagekit does not invoke them")
    return caps
