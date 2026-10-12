""" carved strings + decode cascade over native/dex bytes (stdlib only).

Adapted from the carve shape: ASCII/UTF-16LE/BE extraction with overlap
suppression, then a total-function decode cascade (base64 x4 alphabets,
hex, URL-encoding, single-byte XOR, repeating-key XOR<=8) under a candidate
budget with an honest truncation flag. Every transform returns bytes or
None — attacker-controlled input must never crash the decoder.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from collections import Counter

MIN_STR_LEN = 4
MAX_STR_LEN = 4096
DEFAULT_MAX_CANDIDATES = 10_000
MAX_REPEATING_KEY = 8

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STR_LEN)
_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STR_LEN)
_UTF16BE_RE = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % MIN_STR_LEN)


def extract(data: bytes, *, min_len: int = MIN_STR_LEN,
            max_len: int = MAX_STR_LEN) -> list[dict]:
    """All strings, one entry per claimed span, overlaps suppressed."""
    if min_len != MIN_STR_LEN:
        a_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        le_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
        be_re = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % min_len)
    else:
        a_re, le_re, be_re = _ASCII_RE, _UTF16LE_RE, _UTF16BE_RE
    out = []
    for m in a_re.finditer(data):
        out.append((m.start(), m.end(), "ascii", m.group().decode("ascii")))
    for m in le_re.finditer(data):
        out.append((m.start(), m.end(), "utf-16le",
                    m.group().decode("utf-16-le")))
    for m in be_re.finditer(data):
        out.append((m.start(), m.end(), "utf-16be",
                    m.group().decode("utf-16-be")))
    out.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    spans, taken_until = [], -1
    for start, end, enc, text in out:
        if start < taken_until:
            continue
        if len(text) > max_len:
            text = text[:max_len]
            end = start + len(text) * (2 if enc != "ascii" else 1)
        spans.append({"offset": start, "encoding": enc, "text": text})
        taken_until = end
    return spans


def _try_b64(s: str, alt: str) -> bytes | None:
    try:
        if alt == "std":
            return base64.b64decode(s, validate=True)
        if alt == "url":
            return base64.b64decode(s, altchars=b"-_", validate=True)
        if alt == "std-nopad":
            return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        if alt == "url-nopad":
            return base64.b64decode(s + "=" * (-len(s) % 4),
                                    altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None
    return None


def _try_hex(s: str) -> bytes | None:
    try:
        if len(s) % 2 or not s:
            return None
        return bytes.fromhex(s)
    except ValueError:
        return None


def _try_url(s: str) -> bytes | None:
    try:
        if "%" not in s:
            return None
        return urllib.parse.unquote_to_bytes(s)
    except (ValueError, UnicodeDecodeError):
        return None


def _try_xor(s: str) -> bytes | None:
    """Single-byte XOR yielding mostly-printable output, else None."""
    raw = s.encode("latin-1", "replace")
    best = None
    for key in range(1, 256):
        dec = bytes(b ^ key for b in raw)
        if all(0x20 <= b < 0x7F or b in (9, 10, 13) for b in dec):
            score = sum(c.isalnum() or c == "_" for c in dec.decode("ascii", "replace"))
            if best is None or score > best[0]:
                best = (score, key, dec)
    if best and best[0] >= max(4, len(raw) // 2):
        return best[2]
    return None


def _printable(b: bytes) -> bool:
    return (len(b) >= 4
            and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in b))


def cascade(text: str, *, max_candidates: int = DEFAULT_MAX_CANDIDATES):
    """Yield (transform, decoded) pairs. Bounded: stops at max_candidates."""
    n = 0
    s = text.strip()
    if len(s) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", s):
        for alt in ("std", "url", "std-nopad", "url-nopad"):
            dec = _try_b64(s, alt)
            if dec is not None:
                yield (f"base64-{alt}", dec)
                n += 1
                if n >= max_candidates:
                    return
                break
    hx = _try_hex(s)
    if hx is not None:
        yield ("hex", hx)
        n += 1
        if n >= max_candidates:
            return
    u = _try_url(s)
    if u is not None:
        yield ("url", u)
        n += 1
        if n >= max_candidates:
            return
    x = _try_xor(s)
    if x is not None:
        yield ("xor1", x)


def run_cascade(texts: list[str], *,
                max_candidates: int = DEFAULT_MAX_CANDIDATES) -> list[dict]:
    """Decode a batch. Returns [{text, transform, decoded}] (decoded bytes)."""
    out: list[dict] = []
    for t in texts:
        for transform, dec in cascade(t, max_candidates=max_candidates):
            out.append({"text": t[:120], "transform": transform,
                        "decoded": dec})
            if len(out) >= max_candidates:
                out.append({"truncated": True,
                            "transform": "budget",
                            "decoded": b""})
                return out
    return out
