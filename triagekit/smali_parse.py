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
_MEMBER_RE = re.compile(r"^(\[*(?:L[^;]*;|[BCDFIJSZ]))->([^()\s]+)(\(.*\)\S*)$")
_FIELD_RE = re.compile(r"^(L[^;]*;)->([^:]+):(\S+)$")
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

# Arithmetic/bit-shift binary opcodes (dst, src1, src2; /2addr -> dst,src;
# /lit8|/lit16 -> dst, src, literal). Both int and long variants; the
# float/double names are accepted too (harmless if a disassembler emits
# them) so the coverage counter is not inflated by naming trivia.
_ARITH_BINARY_BASE = frozenset({
    "add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int",
    "or-int", "xor-int", "shl-int", "shr-int", "ushr-int", "rsub-int",
    "add-long", "sub-long", "mul-long", "div-long", "rem-long", "and-long",
    "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
    "add-float", "sub-float", "mul-float", "div-float", "rem-float",
    "add-double", "sub-double", "mul-double", "div-double", "rem-double",
})

# Unary/negation and numeric conversions (dst, src).
_UNARY_BASE = frozenset({
    "neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
    "int-to-long", "int-to-float", "int-to-double", "int-to-byte",
    "int-to-char", "int-to-short",
    "long-to-int", "long-to-float", "long-to-double",
    "float-to-int", "float-to-long", "float-to-double",
    "double-to-int", "double-to-long", "double-to-float",
})

# Comparisons (dst, src1, src2).
_CMP_BASE = frozenset({
    "cmp-long", "cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double",
})

# Opcodes whose destination is a value derived from their source
# registers (taint propagates): arithmetic, conversions, comparisons,
# array-length, instance-of. Read as `opcode.split("/")[0]`.
PROPAGATE_OPS = _ARITH_BINARY_BASE | _UNARY_BASE | _CMP_BASE | frozenset({
    "array-length", "instance-of",
})

# Field access (iget*/iput*: reg,reg,field; sget*/sput*: reg,field) and
# array element writes. These are modelled for syntax + conservative
# transfer (reads -> unknown, writes -> no register def).
_FIELD_OPS = ("iget", "iput", "sget", "sput")

# Directives that open/close non-instruction data blocks inside method
# bodies (annotations, encoded array payloads, enum bodies). Their inner
# lines are data, not instructions, and must not be counted as coverage
# gaps.
_ANN_OPEN = (".annotation", ".subannotation")
_ANN_CLOSE = (".end annotation", ".end subannotation")
_ARRAY_OPEN = (".array-data",)
_ARRAY_CLOSE = (".end array-data",)
_ENUM_OPEN = (".enum",)
_ENUM_CLOSE = (".end enum",)
# Switch payload tables (opcode targets a label declared as
# `.sparse-switch` / `.packed-switch`); their `key -> :label` rows are
# data, not instructions.
_SWITCH_OPEN = (".sparse-switch", ".packed-switch")
_SWITCH_CLOSE = (".end sparse-switch", ".end packed-switch")


def _starts_directive(text: str, prefixes) -> bool:
    for p in prefixes:
        if text == p or text.startswith(p + " ") or text.startswith(p + "\t"):
            return True
    return False


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


def _field_ref(token: str):
    m = _FIELD_RE.match(token.strip())
    if not m:
        return None
    return {"owner": m.group(1), "name": m.group(2), "descriptor": m.group(3)}


def _h_field(opcode: str, operands: str):
    parts = [p.strip() for p in operands.split(",")]
    if opcode.split("/")[0].startswith(("iget", "iput")):
        if (len(parts) != 3 or not _REG_RE.match(parts[0])
                or not _REG_RE.match(parts[1])):
            return None, "expected two registers and a field for %r" % (opcode,)
        ref = _field_ref(parts[2])
        registers = [parts[0], parts[1]]
    else:
        if len(parts) != 2 or not _REG_RE.match(parts[0]):
            return None, "expected one register and a field for %r" % (opcode,)
        ref = _field_ref(parts[1])
        registers = [parts[0]]
    if ref is None:
        return None, "unrecognized field reference for %r" % (opcode,)
    return {"registers": registers, "ref": ref}, ""


def _h_arith(opcode: str, operands: str):
    suffix = opcode.split("/", 1)[1] if "/" in opcode else ""
    parts = [p.strip() for p in operands.split(",")]
    if suffix == "2addr":
        if len(parts) == 2 and all(_REG_RE.match(p) for p in parts):
            return {"registers": parts}, ""
        return None, "expected two registers for %r" % (opcode,)
    if suffix in ("lit8", "lit16") or opcode == "rsub-int":
        if (len(parts) == 3 and _REG_RE.match(parts[0])
                and _REG_RE.match(parts[1])):
            return {"registers": [parts[0], parts[1]]}, ""
        return None, "expected two registers and a literal for %r" % (opcode,)
    if len(parts) == 3 and all(_REG_RE.match(p) for p in parts):
        return {"registers": parts}, ""
    return None, "expected three registers for %r" % (opcode,)


def _h_filled_array(opcode: str, operands: str):
    m = _INVOKE_OPERANDS_RE.match(operands)
    if not m:
        return None, "malformed array register list for %r" % (opcode,)
    registers = _register_list(m.group(1))
    if registers is None:
        return None, "bad register list for %r" % (opcode,)
    if not m.group(2):
        return None, "missing element type for %r" % (opcode,)
    return {"registers": registers}, ""


def _h_instance_of(opcode: str, operands: str):
    parts = [p.strip() for p in operands.split(",")]
    if (len(parts) != 3 or not _REG_RE.match(parts[0])
            or not _REG_RE.match(parts[1]) or not parts[2]):
        return None, "expected two registers and a type for %r" % (opcode,)
    return {"registers": [parts[0], parts[1]]}, ""


def _handler_for(opcode: str):
    base = opcode.split("/")[0]
    if base in _INVOKE_OPS:
        return _h_invoke
    if opcode == "move-exception":
        return _h_single_register
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
    if base.startswith(_FIELD_OPS):
        return _h_field
    if base == "filled-new-array":
        return _h_filled_array
    if opcode.startswith("aget") or opcode.startswith("aput"):
        return _h_three_registers
    if base in _ARITH_BINARY_BASE:
        return _h_arith
    if base in _UNARY_BASE:
        return _h_two_registers
    if base in _CMP_BASE:
        return _h_three_registers
    if opcode == "array-length":
        return _h_two_registers
    if opcode == "instance-of":
        return _h_instance_of
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


def _irrelevant_item(raw, line: int) -> dict:
    return {
        "line": line, "raw": "" if raw is None else str(raw),
        "status": IRRELEVANT, "opcode": "", "registers": [], "ref": None,
        "reason": "", "invoke_static": None,
    }


def parse_lines(lines, start: int = 0) -> list:
    """Parse lines, tracking non-instruction data blocks.

    Lines inside `.annotation` / `.subannotation` / `.array-data` /
    `.enum` blocks are metadata, not instructions. They are returned as
    `irrelevant` (recognized, no value effect) instead of being misread
    as unsupported/malformed coverage gaps. Only lines outside such
    blocks are handed to the instruction grammar.
    """
    items = []
    ann = array = enum = switch = 0
    for offset, raw in enumerate(lines):
        line = start + offset
        text = ("" if raw is None else str(raw)).strip()
        if _starts_directive(text, _ANN_OPEN):
            ann += 1
            items.append(_irrelevant_item(raw, line))
        elif _starts_directive(text, _ANN_CLOSE):
            ann = max(0, ann - 1)
            items.append(_irrelevant_item(raw, line))
        elif _starts_directive(text, _ARRAY_OPEN):
            array += 1
            items.append(_irrelevant_item(raw, line))
        elif _starts_directive(text, _ARRAY_CLOSE):
            array = max(0, array - 1)
            items.append(_irrelevant_item(raw, line))
        elif _starts_directive(text, _ENUM_OPEN):
            enum += 1
            items.append(_irrelevant_item(raw, line))
        elif _starts_directive(text, _ENUM_CLOSE):
            enum = max(0, enum - 1)
            items.append(_irrelevant_item(raw, line))
        elif _starts_directive(text, _SWITCH_OPEN):
            switch += 1
            items.append(_irrelevant_item(raw, line))
        elif _starts_directive(text, _SWITCH_CLOSE):
            switch = max(0, switch - 1)
            items.append(_irrelevant_item(raw, line))
        elif ann or array or enum or switch:
            items.append(_irrelevant_item(raw, line))
        else:
            items.append(parse_line(raw, line))
    return items


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
