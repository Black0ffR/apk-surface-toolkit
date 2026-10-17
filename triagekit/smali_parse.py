"""Conservative shared parser for the smali grammar triagekit models (TF-03).

Deliberately limited: only the documented instruction families are fully
"parsed". Anything instruction-shaped outside that grammar is reported as
"unsupported" (a coverage gap, never silently parsed); operand failures and
non-instruction garbage are "malformed"; valid lines with no taint-relevant
value effect are "irrelevant".

Callers must treat status "parsed" as the only status where registers/ref
are complete; "unsupported" and "malformed" data must not be inferred from.
"""
from __future__ import annotations

import re

PARSED = "parsed"
UNSUPPORTED = "unsupported"
MALFORMED = "malformed"
IRRELEVANT = "irrelevant"

_OPCODE_RE = re.compile(r"^[a-z][a-z0-9/-]*$")
_REG_RE = re.compile(r"^[vp]\d+$")
_MEMBER_RE = re.compile(r"^(L[^;]*;)->([^()\s]+)(\(.*\)\S*)$")
_DECL_RE = re.compile(r"(?:^|\s)([\w<>$-]+)(\(.*\)\S*)$")
_INVOKE_OPERANDS_RE = re.compile(r"^(\{[^}]*\})\s*,\s*(\S+)$")
_RANGE_RE = re.compile(r"^([vp])(\d+)\s*\.\.\s*([vp])(\d+)$")

_MAX_RANGE = 65535

_INVOKE_OPS = frozenset({
    "invoke-virtual", "invoke-super", "invoke-direct",
    "invoke-static", "invoke-interface",
})

_IRRELEVANT_OPCODES = frozenset({
    "nop", "check-cast", "monitor-enter", "monitor-exit", "throw",
    "return", "return-void", "return-wide", "return-object",
    "packed-switch", "sparse-switch",
})

_IRRELEVANT_PREFIXES = ("if-", "goto")


def _strip_comment(text: str) -> str:
    quote = False
    for i, ch in enumerate(text):
        if ch == '"':
            quote = not quote
        elif ch == "#" and not quote:
            return text[:i]
    return text


def _register_list(token: str):
    inner = token[1:-1].strip()
    if not inner:
        return []
    m = _RANGE_RE.match(inner)
    if m:
        if m.group(1) != m.group(3):
            return None
        first, last = int(m.group(2)), int(m.group(4))
        if first > last or last - first > _MAX_RANGE:
            return None
        return ["%s%d" % (m.group(1), i) for i in range(first, last + 1)]
    registers = []
    for part in inner.split(","):
        reg = part.strip()
        if not _REG_RE.match(reg):
            return None
        registers.append(reg)
    return registers


def _is_irrelevant(opcode: str) -> bool:
    return opcode in _IRRELEVANT_OPCODES or opcode.startswith(_IRRELEVANT_PREFIXES)


def _h_invoke(opcode: str, operands: str):
    m = _INVOKE_OPERANDS_RE.match(operands)
    if not m:
        return None, "malformed invoke operands for %r" % (opcode,)
    registers = _register_list(m.group(1))
    if registers is None:
        return None, "bad register list for %r" % (opcode,)
    ref_m = _MEMBER_RE.match(m.group(2))
    if not ref_m:
        return None, "unrecognized method reference for %r" % (opcode,)
    return {
        "registers": registers,
        "ref": {"owner": ref_m.group(1), "name": ref_m.group(2),
                "descriptor": ref_m.group(3)},
        "invoke_static": opcode.split("/")[0] == "invoke-static",
    }, ""


def _h_single_register(opcode: str, operands: str):
    reg = operands.strip()
    if not _REG_RE.match(reg):
        return None, "expected one register for %r, got %r" % (opcode, operands)
    return {"registers": [reg]}, ""


def _h_two_registers(opcode: str, operands: str):
    parts = [p.strip() for p in operands.split(",")]
    if len(parts) != 2 or not all(_REG_RE.match(p) for p in parts):
        return None, "expected two registers for %r, got %r" % (opcode, operands)
    return {"registers": parts}, ""


def _h_three_registers(opcode: str, operands: str):
    parts = [p.strip() for p in operands.split(",")]
    if len(parts) != 3 or not all(_REG_RE.match(p) for p in parts):
        return None, "expected three registers for %r, got %r" % (opcode, operands)
    return {"registers": parts}, ""


def _h_const(opcode: str, operands: str):
    reg, sep, rest = operands.partition(",")
    reg, rest = reg.strip(), rest.strip()
    if not sep or not _REG_RE.match(reg):
        return None, "expected register then literal for %r" % (opcode,)
    if opcode.startswith("const-string"):
        if len(rest) < 2 or not rest.startswith('"') or not rest.endswith('"'):
            return None, "const-string operand is not a quoted string"
    elif not rest:
        return None, "missing literal for %r" % (opcode,)
    return {"registers": [reg]}, ""


def _h_register_and_rest(opcode: str, operands: str):
    reg, sep, rest = operands.partition(",")
    reg, rest = reg.strip(), rest.strip()
    if not sep or not _REG_RE.match(reg) or not rest:
        return None, "expected register and type for %r" % (opcode,)
    return {"registers": [reg]}, ""


def _h_new_array(opcode: str, operands: str):
    parts = [p.strip() for p in operands.split(",")]
    if (len(parts) != 3 or not _REG_RE.match(parts[0])
            or not _REG_RE.match(parts[1]) or not parts[2]):
        return None, "expected two registers and a type for %r" % (opcode,)
    return {"registers": [parts[0], parts[1]]}, ""


def _h_fill_array_data(opcode: str, operands: str):
    reg, sep, label = operands.partition(",")
    reg, label = reg.strip(), label.strip()
    if not sep or not _REG_RE.match(reg) or not label:
        return None, "expected register and label for %r" % (opcode,)
    return {"registers": [reg]}, ""


def _handler_for(opcode: str):
    if opcode.split("/")[0] in _INVOKE_OPS:
        return _h_invoke
    if opcode.startswith("move-result"):
        return _h_single_register
    if opcode.startswith("move"):
        return _h_two_registers
    if opcode.startswith("const"):
        return _h_const
    if opcode == "new-instance":
        return _h_register_and_rest
    if opcode == "new-array":
        return _h_new_array
    if opcode.startswith("aget"):
        return _h_three_registers
    if opcode == "fill-array-data":
        return _h_fill_array_data
    return None


def parse_line(raw, line: int = 0) -> dict:
    raw_text = "" if raw is None else str(raw)
    item = {
        "line": line, "raw": raw_text, "status": IRRELEVANT, "opcode": "",
        "registers": [], "ref": None, "reason": "", "invoke_static": None,
    }
    text = raw_text.strip()
    if not text or text.startswith(("#", ":", ".")):
        return item
    body = _strip_comment(text).strip()
    if not body:
        return item
    parts = body.split(None, 1)
    if not _OPCODE_RE.match(parts[0]):
        item["status"] = MALFORMED
        item["reason"] = "not an instruction: %r" % (parts[0],)
        return item
    opcode = parts[0]
    operands = parts[1] if len(parts) > 1 else ""
    item["opcode"] = opcode
    if _is_irrelevant(opcode):
        return item
    handler = _handler_for(opcode)
    if handler is None:
        item["status"] = UNSUPPORTED
        item["reason"] = "no grammar rule for opcode %r" % (opcode,)
        return item
    parsed, reason = handler(opcode, operands)
    if parsed is None:
        item["status"] = MALFORMED
        item["reason"] = reason
        return item
    item["status"] = PARSED
    item["registers"] = parsed["registers"]
    item["ref"] = parsed.get("ref")
    item["invoke_static"] = parsed.get("invoke_static")
    return item


def parse_lines(lines, start: int = 0) -> list:
    return [parse_line(raw, start + offset) for offset, raw in enumerate(lines)]


def method_declaration(decl: str):
    text = _strip_comment("" if decl is None else str(decl)).strip()
    if text.startswith("."):
        parts = text.split(None, 1)
        if parts[0] != ".method":
            return None
        text = parts[1] if len(parts) > 1 else ""
    m = _DECL_RE.search(text)
    if not m:
        return None
    return m.group(1), m.group(2)
