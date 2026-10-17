"""Basic-block control-flow graph for smali method bodies (TF-02 Stage 2).

Conservative on purpose:

- only documented control-flow opcodes are interpreted (``goto*``, ``if-*``,
  ``packed-switch``/``sparse-switch``, ``return*``, ``throw``); any other
  opcode falls through even when its grammar is unsupported (the caller
  records that separately as a coverage gap);
- a referenced label that is not defined in the body never gets an invented
  successor: it is surfaced in ``missing_targets``/``missing_labels``;
- a switch contributes edges only when its payload resolves to case labels;
  otherwise it is counted in ``unresolved_switches`` and contributes none
  (a switch has no fall-through).

Labels are stored without the leading colon. Payload spans (the
``.packed-switch``/``.sparse-switch`` data regions) become one ``payload``
block of their own: their data label(s) map to it, their case labels are
references only and are never re-defined by the payload.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import smali_parse as SP

_LABEL_RE = re.compile(r"^:([A-Za-z0-9_$-]+)")
_LABEL_TOKEN_RE = re.compile(r":([A-Za-z0-9_$-]+)")
_PAYLOAD_START = (".packed-switch", ".sparse-switch")
_PAYLOAD_END = (".end packed-switch", ".end sparse-switch")

TERMINATORS = ("goto", "if", "switch", "return", "throw")


@dataclass(frozen=True)
class BasicBlock:
    block_id: str
    start_line: int
    end_line: int
    lines: tuple[str, ...]
    labels: tuple[str, ...]
    payload_targets: tuple[str, ...]
    successors: tuple[str, ...]
    terminator: str
    missing_targets: tuple[str, ...] = ()


@dataclass(frozen=True)
class Cfg:
    blocks: tuple[BasicBlock, ...]
    label_to_block: dict[str, str]
    entry: str
    missing_labels: tuple[str, ...]
    unresolved_switches: int


def _bare(raw: str) -> str:
    text = ("" if raw is None else str(raw)).strip()
    if "#" in text:
        text = text.split("#", 1)[0].rstrip()
    return text


def _label_of(raw: str) -> str | None:
    m = _LABEL_RE.match(_bare(raw))
    return m.group(1) if m else None


def _target_token(raw: str) -> str | None:
    m = _LABEL_TOKEN_RE.search(_bare(raw))
    return m.group(1) if m else None


def _terminator_for(opcode: str) -> str:
    if opcode.startswith("goto"):
        return "goto"
    if opcode.startswith("if-"):
        return "if"
    if opcode in ("packed-switch", "sparse-switch"):
        return "switch"
    if opcode.startswith("return"):
        return "return"
    if opcode == "throw":
        return "throw"
    return ""


def _find_payload_spans(body: list[str]) -> list[tuple[int, int, int]]:
    spans: list[tuple[int, int, int]] = []
    n = len(body)
    k = 0
    while k < n:
        if _bare(body[k]).startswith(_PAYLOAD_START):
            j = k + 1
            while j < n and not _bare(body[j]).startswith(_PAYLOAD_END):
                j += 1
            end = j if j < n else n - 1
            start = k
            while start - 1 >= 0 and _label_of(body[start - 1]) is not None:
                start -= 1
            spans.append((start, k, end))
            k = end + 1
        else:
            k += 1
    return spans


def build(body_lines) -> Cfg:
    """Build the CFG for one method body (list of raw smali lines)."""
    body = list(body_lines or ())
    n = len(body)
    if n == 0:
        return Cfg(blocks=(), label_to_block={}, entry="",
                   missing_labels=(), unresolved_switches=0)
    items = [SP.parse_line(raw, idx) for idx, raw in enumerate(body)]
    spans = _find_payload_spans(body)
    span_by_start = {s: (d, e) for s, d, e in spans}

    def _in_span(idx: int) -> bool:
        return any(s <= idx <= e for s, _d, e in spans)

    points = {0, n}
    for s, _d, e in spans:
        points.add(s)
        points.add(e + 1)
    for k in range(n):
        if _in_span(k):
            continue
        if _label_of(body[k]) is not None:
            if k > 0 and _label_of(body[k - 1]) is not None \
                    and not _in_span(k - 1):
                continue
            points.add(k)
        if _terminator_for(items[k]["opcode"]):
            points.add(k + 1)
    ordered = sorted(p for p in points if 0 <= p <= n)
    ranges = [(a, b - 1) for a, b in zip(ordered, ordered[1:]) if a <= b - 1]

    drafts = []
    for idx, (a, b) in enumerate(ranges):
        bid = f"b{idx}"
        span = span_by_start.get(a)
        if span is not None:
            directive, end = span
            labels = tuple(lb for lb in
                           (_label_of(body[k]) for k in range(a, directive + 1))
                           if lb)
            seen: list[str] = []
            for k in range(directive + 1, min(end, n - 1) + 1):
                for lb in _LABEL_TOKEN_RE.findall(_bare(body[k])):
                    if lb not in seen:
                        seen.append(lb)
            drafts.append((bid, a, b, labels, tuple(seen), "payload", ""))
        else:
            labels = tuple(lb for lb in
                           (_label_of(body[k]) for k in range(a, b + 1)) if lb)
            last_op, last_raw = "", ""
            for k in range(a, b + 1):
                if items[k]["opcode"]:
                    last_op, last_raw = items[k]["opcode"], body[k]
            term = _terminator_for(last_op) or ("end" if b == n - 1
                                                else "fallthrough")
            drafts.append((bid, a, b, labels, (), term, last_raw))

    label_to_bid: dict[str, str] = {}
    for bid, _a, _b, labels, _t, _term, _raw in drafts:
        for lb in labels:
            label_to_bid[lb] = bid
    by_bid = {d[0]: d for d in drafts}
    next_of = {f"b{i}": (f"b{i + 1}" if i + 1 < len(ranges) else None)
               for i in range(len(ranges))}

    missing: set[str] = set()

    def resolve(label: str) -> str | None:
        bid = label_to_bid.get(label)
        if bid is None:
            missing.add(label)
        return bid

    unresolved = 0
    finals: list[BasicBlock] = []
    for bid, a, b, labels, targets, term, last_raw in drafts:
        succ: list[str] = []
        missing_targets: list[str] = []
        if term in ("payload", "return", "throw", "end"):
            pass
        elif term == "goto":
            t = _target_token(last_raw)
            if t is not None:
                tb = resolve(t)
                if tb is None:
                    missing_targets.append(t)
                else:
                    succ.append(tb)
        elif term == "if":
            nxt = next_of[bid]
            if nxt is not None and by_bid[nxt][5] != "payload":
                succ.append(nxt)
            t = _target_token(last_raw)
            if t is not None:
                tb = resolve(t)
                if tb is None:
                    missing_targets.append(t)
                elif tb not in succ:
                    succ.append(tb)
        elif term == "switch":
            t = _target_token(last_raw)
            pb = resolve(t) if t is not None else None
            if pb is None or by_bid[pb][5] != "payload" or not by_bid[pb][4]:
                unresolved += 1
            else:
                for lb in by_bid[pb][4]:
                    tb = resolve(lb)
                    if tb is None:
                        missing_targets.append(lb)
                    elif tb not in succ:
                        succ.append(tb)
        elif term == "fallthrough":
            nxt = next_of[bid]
            if nxt is not None and by_bid[nxt][5] != "payload":
                succ.append(nxt)
        finals.append(BasicBlock(
            block_id=bid, start_line=a, end_line=b,
            lines=tuple(body[a:b + 1]), labels=labels,
            payload_targets=targets, successors=tuple(succ),
            terminator=term, missing_targets=tuple(missing_targets)))

    return Cfg(blocks=tuple(finals), label_to_block=label_to_bid,
               entry=finals[0].block_id,
               missing_labels=tuple(sorted(missing)),
               unresolved_switches=unresolved)
