"""Windowed entropy + chi-square contrast gate over dex/.so bytes (stdlib).

Adapted from the entropyfloor shape (coarse windows, median-vs-peak
contrast, chi-square uniformity, section-aware exclusions) without numpy:
byte histograms via Counter, sampled windows to fit a phone CPU budget.
Answers one question: does this executable region look encrypted/packed?
"""
from __future__ import annotations

import math
import os
import zipfile
from collections import Counter

WINDOW = 4096
SAMPLE_WINDOWS = 64
ENTROPY_HIGH = 7.5
CONTRAST_MIN = 1.5
CHI_UNIFORM_MAX = 400.0


def _shannon_bytes(buf: bytes) -> float:
    if not buf:
        return 0.0
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in Counter(buf).values())


def _chi_square(buf: bytes) -> float:
    """Uniformity chi-square over 256 byte values (low = uniform/random)."""
    n = len(buf)
    if n == 0:
        return float("inf")
    exp = n / 256.0
    return sum((Counter(buf).get(b, 0) - exp) ** 2 / exp for b in range(256))


def _windows(data: bytes, size: int = WINDOW,
             limit: int = SAMPLE_WINDOWS) -> list[bytes]:
    if len(data) <= size * limit:
        return [data[i:i + size] for i in range(0, len(data), size)]
    step = max(1, (len(data) - size) // limit)
    return [data[i:i + size] for i in range(0, len(data) - size + 1, step)][:limit]


def scan_region(data: bytes) -> dict:
    """Classify one executable region. Never raises on garbage input."""
    wins = _windows(data)
    if not wins:
        return {"encrypted": False, "peak": 0.0, "median": 0.0,
                "contrast": 0.0, "chi": float("inf")}
    ents = sorted(_shannon_bytes(w) for w in wins)
    peak, median = ents[-1], ents[len(ents) // 2]
    contrast = peak - median
    # Uniformly random data has no contrast (every window ~8.0) but a
    # near-perfect chi-square; partially-encrypted files show contrast.
    chi = _chi_square(b"".join(wins[:16]))
    encrypted = peak >= ENTROPY_HIGH and (
        contrast >= CONTRAST_MIN or chi < CHI_UNIFORM_MAX)
    return {"encrypted": bool(encrypted), "peak": round(peak, 2),
            "median": round(median, 2), "contrast": round(contrast, 2),
            "chi": round(chi, 1)}


def is_encrypted_region(data: bytes) -> bool:
    return scan_region(data)["encrypted"]


def scan_apk(apk: str, *, dex_cap: int = 2_000_000,
             so_cap: int = 1_000_000) -> list[dict]:
    """Scan classes*.dex + lib/**/*.so. Returns [{file, peak, chi, ...}]."""
    out: list[dict] = []
    try:
        with zipfile.ZipFile(apk) as z:
            names = [n for n in z.namelist()
                     if n.startswith("classes") and n.endswith(".dex")
                     or n.startswith("lib/") and n.endswith(".so")]
            for n in names[:20]:
                try:
                    raw = z.read(n)
                except Exception:
                    continue
                cap = so_cap if n.startswith("lib/") else dex_cap
                rec = scan_region(raw[:cap])
                if rec["encrypted"]:
                    rec["file"] = n
                    out.append(rec)
    except zipfile.BadZipFile:
        pass
    return out
