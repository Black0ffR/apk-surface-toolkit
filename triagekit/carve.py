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
import hashlib
import math
import re
import urllib.parse
from collections import Counter

MIN_STR_LEN = 4
MAX_STR_LEN = 4096
DEFAULT_MAX_CANDIDATES = 10_000
MAX_REPEATING_KEY = 8
MAX_XOR_KEYS = 255   # single-byte key space, per plan §12.3 strict cap
# Decode cascade is single-pass by construction; `MAX_DECODING_DEPTH`
# documents that bound so any future nesting must raise it explicitly.
MAX_DECODING_DEPTH = 1
SENSITIVE_TOKEN_MIN = 20   # long high-entropy token = likely secret
SENSITIVE_ENTROPY_MIN = 4.5  # same convention as regex rules' entropy_min

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


def _try_xor_best(s: str, max_keys: int = MAX_XOR_KEYS) -> tuple[bytes | None, int | None]:
    """Single-byte XOR yielding mostly-printable output, else (None, None).

    Keys are capped at `max_keys` attempts (1..min(255, max_keys)); this
    bounds the XOR search per string instead of relying on implicit
    constants (plan §12.3).
    """
    raw = s.encode("latin-1", "replace")
    best = None
    for key in range(1, min(256, max_keys + 1)):
        dec = bytes(b ^ key for b in raw)
        if all(0x20 <= b < 0x7F or b in (9, 10, 13) for b in dec):
            score = sum(c.isalnum() or c == "_" for c in dec.decode("ascii", "replace"))
            if best is None or score > best[0]:
                best = (score, key, dec)
    if best and best[0] >= max(4, len(raw) // 2):
        return best[2], best[1]
    return None, None


def _try_xor(s: str) -> bytes | None:
    """Legacy single-byte XOR entry point (uncapped, full key range)."""
    dec, _ = _try_xor_best(s)
    return dec


def _printable(b: bytes) -> bool:
    return (len(b) >= 4
            and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in b))


_B64STD_SUB_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")
_B64URL_SUB_RE = re.compile(r"[A-Za-z0-9\-_]{20,}")
_HEX_SUB_RE = re.compile(r"[0-9a-fA-F]{16,}")


def _cascade_units(text: str, *, max_candidates: int = DEFAULT_MAX_CANDIDATES,
                   max_xor_keys: int = MAX_XOR_KEYS):
    """Yield (transform_name, matched_unit, decoded, params) tuples.

    `matched_unit` is the exact substring of `text` the transform consumed,
    letting callers anchor decoded output back into artifact byte offsets.
    Yields are bounded by max_candidates; XOR attempts by max_xor_keys;
    decode depth is fixed at MAX_DECODING_DEPTH (single pass).
    """
    n = 0
    s = text.strip()
    whole = False
    if len(s) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", s):
        for alt in ("std", "url", "std-nopad", "url-nopad"):
            dec = _try_b64(s, alt)
            # Printable only: letter/dash soup (prefix-junk--tail) matches
            # the alphabet but decodes to garbage — claiming it would both
            # burn budget and suppress the substring sweep below.
            if dec is not None and _printable(dec):
                yield (f"base64-{alt}", s, dec, {"variant": alt})
                n += 1
                whole = True
                if n >= max_candidates:
                    return
                break
    if not whole:
        # Dash joins English words into one long run, so sweep the std and
        # url alphabets separately: "prefix-junk--<BLOB>" still resolves.
        seen = set()
        for sub_re, alts in ((_B64STD_SUB_RE, ("std", "std-nopad")),
                             (_B64URL_SUB_RE, ("url", "url-nopad"))):
            for m in sub_re.finditer(s):
                sub = m.group(0)
                if sub in seen:
                    continue
                seen.add(sub)
                for alt in alts:
                    dec = _try_b64(sub, alt)
                    if dec is not None and _printable(dec):
                        yield (f"base64-{alt}", sub, dec, {"variant": alt})
                        n += 1
                        break
                if n >= max_candidates or len(seen) >= 16:
                    return
        for m in _HEX_SUB_RE.finditer(s):
            sub = m.group(0)
            if len(sub) % 2:
                sub = sub[:-1]
            hx = _try_hex(sub)
            if hx is not None and _printable(hx):
                yield ("hex", sub, hx, {})
                n += 1
                if n >= max_candidates:
                    return
    hx = _try_hex(s)
    if hx is not None:
        yield ("hex", s, hx, {})
        n += 1
        if n >= max_candidates:
            return
    u = _try_url(s)
    if u is not None:
        yield ("url", s, u, {})
        n += 1
        if n >= max_candidates:
            return
    x, key = _try_xor_best(s, max_xor_keys)
    if x is not None:
        yield ("xor1", s, x, {"key": key})


def cascade(text: str, *, max_candidates: int = DEFAULT_MAX_CANDIDATES,
            max_xor_keys: int = MAX_XOR_KEYS):
    """Yield (transform, decoded) pairs. Bounded: stops at max_candidates.

    Whole-text attempts first; then substring sweep so a blob embedded in
    a longer run (prefix junk, padding) is still reached. Substring hits
    are capped per span to avoid runs exploding into findings.
    """
    for name, _unit, dec, _params in _cascade_units(
            text, max_candidates=max_candidates, max_xor_keys=max_xor_keys):
        yield (name, dec)


def cascade_units(text: str, *, max_candidates: int = DEFAULT_MAX_CANDIDATES,
                  max_xor_keys: int = MAX_XOR_KEYS):
    """Public units view of the cascade (see _cascade_units)."""
    yield from _cascade_units(text, max_candidates=max_candidates,
                              max_xor_keys=max_xor_keys)


def run_cascade_units(texts: list[str], *,
                      max_candidates: int = DEFAULT_MAX_CANDIDATES,
                      max_xor_keys: int = MAX_XOR_KEYS) -> list[dict]:
    """Decode a batch. Returns [{text, transform, decoded, unit, params}].

    Same ordering/budget as run_cascade, plus the matched `unit` substring
    and transform `params` (base64 variant, XOR key) for provenance.
    """
    out: list[dict] = []
    for t in texts:
        for name, unit, dec, params in _cascade_units(
                t, max_candidates=max_candidates, max_xor_keys=max_xor_keys):
            out.append({"text": t[:120], "transform": name,
                        "decoded": dec, "unit": unit, "params": params})
            if len(out) >= max_candidates:
                out.append({"truncated": True,
                            "transform": "budget",
                            "decoded": b""})
                return out
    return out


def run_cascade(texts: list[str], *,
                max_candidates: int = DEFAULT_MAX_CANDIDATES) -> list[dict]:
    """Decode a batch. Returns [{text, transform, decoded}] (decoded bytes)."""
    return [{k: r[k] for k in ("text", "transform", "decoded")}
            for r in run_cascade_units(texts, max_candidates=max_candidates)]


# ---------------------------------------------------------------- NA-01
# Evidence contract for carved/decoded items (plan §12.2): source hash,
# byte offsets/lengths, transform details, decoded hash, printable ratio,
# and explicit candidate confidence. Presentation redaction keeps likely
# secrets out of previews without mutating the underlying evidence bytes.


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for c in data if 0x20 <= c < 0x7F or c in (9, 10, 13))
    return round(ok / len(data), 4)


def _shannon_str(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


_SENSITIVE_SHAPES = re.compile(
    r"(AKIA|ASIA)[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_\-]{35}"
    r"|gh[pou]_[A-Za-z0-9]{20,}"
    r"|sk_live_[0-9a-zA-Z]{10,}"
    r"|xox[bposa]-[0-9A-Za-z\-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9/+_=]{%d,}" % SENSITIVE_TOKEN_MIN)


def looks_sensitive(text: str) -> bool:
    """Heuristic: credential/key shapes, or long high-entropy tokens.

    Same convention as regex rules' entropy_min >= 4.5 on >=20-char tokens.
    This gates presentation redaction only; it never alters evidence bytes.
    """
    if _SENSITIVE_SHAPES.search(text or ""):
        return True
    return any(_shannon_str(m) >= SENSITIVE_ENTROPY_MIN
               for m in _LONG_TOKEN.findall(text or ""))


def redact(value: str, *, keep: int = 6) -> str:
    """Presentation redaction: short prefix plus a digest of the value."""
    if value is None:
        return ""
    h = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
    prefix = value[:keep] if len(value) > keep else ""
    return f"{prefix}…[redacted:{h}]"


_ENCODINGS = {"ascii": ("ascii", 1),
              "utf-16le": ("utf-16-le", 2),
              "utf-16be": ("utf-16-be", 2)}


def cascade_evidence(data: bytes, spans: list[dict], *, library: str,
                     source_artifact_sha256: str,
                     max_candidates: int = DEFAULT_MAX_CANDIDATES,
                     max_xor_keys: int = MAX_XOR_KEYS,
                     include_raw: bool = False,
                     max_raw_records: int = 64,
                     redact_secrets: bool = True) -> list[dict]:
    """Evidence records for carved spans + decoded candidates (plan §12.2).

    `spans` comes from extract(data). Offsets are artifact byte offsets:
    span start plus the matched unit's position inside the span (first
    occurrence; UTF-16 spans count 2 bytes per char). Records are deduped
    by decoded hash; decoded candidates are bounded by max_candidates and
    an explicit truncation sentinel, raw strings by max_raw_records.
    Evidence values are exact; only `decoded_text_preview` is presentation
    (redacted when the decoded text looks sensitive).
    """
    out: list[dict] = []
    seen_hashes: set[str] = set()
    remaining = max(0, int(max_candidates))

    def _base_record(raw_offset: int, raw_len: int, enc_or_tx: str,
                     params: dict, dec: bytes, preview: str) -> dict:
        return {
            "source_artifact_sha256": source_artifact_sha256,
            "library": library,
            "file_offset": raw_offset,
            "length": raw_len,
            "encoding_or_transform": enc_or_tx,
            "transform_parameters": params,
            "decoded_sha256": _sha_bytes(dec),
            "printable_ratio": printable_ratio(dec),
            "decoded_text_preview": preview,
            "classification": "candidate-string",
            "confidence": "candidate",
            "validation": "not_runtime_verified",
        }

    for sp in spans:
        raw_offset = sp["offset"]
        encoding = sp.get("encoding", "ascii")
        text = sp.get("text", "")
        if encoding not in _ENCODINGS:
            continue
        codec, char_bytes = _ENCODINGS[encoding]

        if include_raw:
            raws_so_far = sum(1 for r in out
                              if r.get("encoding_or_transform") == "raw-string")
            if raws_so_far < max_raw_records:
                raw_bytes = text.encode(codec, "replace")
                _dedup_push(out, _base_record(raw_offset, len(raw_bytes),
                                              "raw-string", {}, raw_bytes,
                                              text), seen_hashes)

        if remaining <= 0:
            break
        for name, unit, dec, params in _cascade_units(
                text, max_candidates=remaining, max_xor_keys=max_xor_keys):
            pos = text.find(unit)
            if pos < 0:
                pos = 0
            preview = dec.decode("utf-8", "replace")
            sensitive = looks_sensitive(preview)
            if sensitive and redact_secrets:
                preview = redact(preview)
            enc_name = ("base64" if name.startswith("base64-")
                        else "xor-byte" if name == "xor1"
                        else name)
            if name.startswith("base64-"):
                params = dict(params, variant=name.split("base64-", 1)[1])
            rec = _base_record(raw_offset + pos * char_bytes,
                               len(unit) * char_bytes, enc_name, params,
                               dec, preview)
            if _dedup_push(out, rec, seen_hashes) is not None:
                remaining -= 1
                if remaining <= 0:
                    out.append({"truncated": True, "library": library,
                                "encoding_or_transform": "budget",
                                "classification": "candidate-string"})
                    return out
    return out


def _sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _dedup_push(out: list, rec: dict, seen: set) -> dict | None:
    h = rec.get("decoded_sha256")
    if h is None or h in seen:
        return None
    seen.add(h)
    out.append(rec)
    return rec
