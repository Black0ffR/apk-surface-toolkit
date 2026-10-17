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


def scan_region_detailed(data: bytes, *, window_size: int = WINDOW,
                         max_windows: int = SAMPLE_WINDOWS,
                         entropy_high: float = ENTROPY_HIGH,
                         contrast_min: float = CONTRAST_MIN,
                         chi_uniform_max: float = CHI_UNIFORM_MAX) -> dict:
    """Explainable windowed entropy record (plan §12.2 contract).

    Per-window start/end/size/entropy plus why each window was flagged;
    numeric scores stay separate from the heuristic classification, which
    is always a candidate judgment with validation not_runtime_verified
    (scoring says higher entropy/closer-to-uniform, nothing proves it is
    encrypted content).
    """
    specs = _window_specs(data, window_size, max_windows)
    if len(specs) > max_windows:
        specs = specs[:max_windows]
    windows = []
    reasons: list[str] = []
    for start, buf in specs:
        ent = _shannon_bytes(buf)
        flagged = ent >= entropy_high
        win = {"start": start, "end": start + len(buf), "size": len(buf),
               "entropy": round(ent, 4), "flagged": flagged,
               "flag_reason": (f"window entropy {ent:.2f} >= threshold "
                               f"{entropy_high}") if flagged else ""}
        windows.append(win)

    ents = sorted(w["entropy"] for w in windows)
    if not specs:
        return {"windows": [], "score": 0.0,
                "baseline": {"method": "median-window-shannon-entropy",
                             "value": 0.0},
                "comparison": {"method": "chi-square-uniformity-256",
                               "value": None},
                "classification": {"value": "not-flagged", "heuristic": True,
                                   "validation": "not_runtime_verified"},
                "reasons": ["region empty; no windows evaluated"],
                "window_size": window_size, "windows_evaluated": 0}
    peak = ents[-1]
    median = ents[len(ents) // 2]
    contrast = peak - median
    chi = _chi_square(b"".join(buf for _s, buf in specs[:16]))
    encrypted = peak >= entropy_high and (
        contrast >= contrast_min or chi < chi_uniform_max)
    reasons.append(f"peak window entropy {peak:.2f} (threshold {entropy_high})")
    if contrast >= contrast_min:
        reasons.append(f"median-vs-peak contrast {contrast:.2f} >= {contrast_min}")
    if chi < chi_uniform_max:
        reasons.append(f"chi-square uniformity {chi:.1f} < {chi_uniform_max}")
    if not encrypted:
        reasons = ["heuristic gate not met"]
    return {
        "windows": windows,
        "score": round(peak, 2),
        "baseline": {"method": "median-window-shannon-entropy",
                     "value": round(median, 2)},
        "comparison": {"method": "chi-square-uniformity-256",
                       "value": None if not math.isfinite(chi)
                       else round(chi, 1)},
        "classification": {
            "value": "candidate-encrypted" if encrypted else "not-flagged",
            "heuristic": True,
            "validation": "not_runtime_verified",
        },
        "reasons": reasons,
        "window_size": window_size,
        "windows_evaluated": len(windows),
    }


def _window_specs(data: bytes, size: int = WINDOW,
                  limit: int = SAMPLE_WINDOWS) -> list[tuple[int, bytes]]:
    """Windows with their start offsets (exact legacy selection order)."""
    if len(data) <= size * limit:
        return [(i, data[i:i + size]) for i in range(0, len(data), size)]
    step = max(1, (len(data) - size) // limit)
    return [(i, data[i:i + size])
            for i in range(0, len(data) - size + 1, step)][:limit]


def _windows(data: bytes, size: int = WINDOW,
             limit: int = SAMPLE_WINDOWS) -> list[bytes]:
    return [buf for _start, buf in _window_specs(data, size, limit)]


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
