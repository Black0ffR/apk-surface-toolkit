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
# Fraction-of-windows gates. A whole-region encryption shows a sustained
# high-entropy fraction (few low windows); an embedded encrypted blob or a
# crypto constant table shows an isolated fraction (one/few high windows
# amid otherwise ordinary code). Peak/contrast alone conflates the two.
HIGH_FRACTION_SUSTAINED = 0.6
HIGH_FRACTION_ISOLATED_MAX = 0.25


def classify_region_kind(name: str) -> str:
    """`dex` for classes*.dex, else `native` (reporting only, no verdict)."""
    base = name.rsplit("/", 1)[-1]
    return "dex" if base.startswith("classes") and base.endswith(".dex") \
        else "native"


def _entropy_indicators(ents: list[float], entropy_high: float) -> dict:
    """Evidence-backed fraction indicators for one region.

    `state` is deliberately not a binary verdict:
      - sustained-high-entropy: most windows are high (whole-region payload)
      - isolated-high-entropy-region: a minority of windows are high
        (embedded blob / constant table), the region as a whole is not
      - mixed-entropy / low-entropy: neither pattern
    """
    total = len(ents)
    high = [e for e in ents if e >= entropy_high]
    frac = (len(high) / total) if total else 0.0
    if total == 0:
        state = "indeterminate"
    elif frac >= HIGH_FRACTION_SUSTAINED:
        state = "sustained-high-entropy"
    elif 0 < frac <= HIGH_FRACTION_ISOLATED_MAX:
        state = "isolated-high-entropy-region"
    elif frac > 0:
        state = "mixed-entropy"
    else:
        state = "low-entropy"
    return {
        "windows_total": total,
        "windows_high": len(high),
        "high_fraction": round(frac, 4),
        "sustained": state == "sustained-high-entropy",
        "isolated": state == "isolated-high-entropy-region",
        "state": state,
    }


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

    all_ents = [w["entropy"] for w in windows]
    if not specs:
        return {"windows": [], "score": 0.0,
                "baseline": {"method": "median-window-shannon-entropy",
                             "value": 0.0},
                "comparison": {"method": "chi-square-uniformity-256",
                               "value": None},
                "classification": {"value": "not-flagged", "heuristic": True,
                                   "validation": "not_runtime_verified"},
                "indicators": _entropy_indicators([], entropy_high),
                "state": "indeterminate",
                "reasons": ["region empty; no windows evaluated"],
                "window_size": window_size, "windows_evaluated": 0}
    ents = sorted(all_ents)
    peak = ents[-1]
    median = ents[len(ents) // 2]
    contrast = peak - median
    chi = _chi_square(b"".join(buf for _s, buf in specs[:16]))
    ind = _entropy_indicators(all_ents, entropy_high)
    # Whole-region verdict is the sustained fraction, NOT peak/contrast:
    # a single high window no longer flips the region, and a uniformly high
    # payload (no contrast, non-uniform chi) is no longer missed.
    encrypted = ind["sustained"]
    reasons.append(f"high-entropy windows {ind['windows_high']}/"
                   f"{ind['windows_total']} (fraction {ind['high_fraction']}, "
                   f"threshold {HIGH_FRACTION_SUSTAINED})")
    reasons.append(f"peak window entropy {peak:.2f} (threshold {entropy_high})")
    reasons.append(f"median-window entropy {median:.2f}, contrast {contrast:.2f}")
    if math.isfinite(chi):
        reasons.append(f"chi-square uniformity {chi:.1f}")
    if ind["isolated"]:
        reasons.append("isolated high-entropy region: minority of windows; "
                       "not whole-region encryption")
    elif ind["state"] == "mixed-entropy":
        reasons.append("mixed entropy: high windows below the sustained fraction")
    elif not encrypted:
        reasons.append("whole-region encryption not indicated")
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
        "indicators": ind,
        "state": ind["state"],
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
    """Classify one executable region. Never raises on garbage input.

    `encrypted` means the region as a whole is sustained-high-entropy
    (whole-region payload), not merely that one window is high.
    """
    wins = _windows(data)
    if not wins:
        return {"encrypted": False, "peak": 0.0, "median": 0.0,
                "contrast": 0.0, "chi": float("inf"),
                "state": "indeterminate", "high_fraction": 0.0,
                "windows_high": 0, "windows_total": 0}
    ent_list = [_shannon_bytes(w) for w in wins]
    ents = sorted(ent_list)
    peak, median = ents[-1], ents[len(ents) // 2]
    contrast = peak - median
    chi = _chi_square(b"".join(wins[:16]))
    ind = _entropy_indicators(ent_list, ENTROPY_HIGH)
    return {"encrypted": bool(ind["sustained"]), "peak": round(peak, 2),
            "median": round(median, 2), "contrast": round(contrast, 2),
            "chi": round(chi, 1), "state": ind["state"],
            "high_fraction": ind["high_fraction"],
            "windows_high": ind["windows_high"],
            "windows_total": ind["windows_total"]}


def is_encrypted_region(data: bytes) -> bool:
    return scan_region(data)["encrypted"]


def scan_apk(apk: str, *, dex_cap: int = 2_000_000,
             so_cap: int = 1_000_000) -> list[dict]:
    """Scan classes*.dex + lib/**/*.so. Returns region records.

    Each record carries `region_kind` (`dex`/`native`), the fraction
    `indicators`, and `state`. Only a sustained whole-region payload is
    `encrypted`; an isolated high-entropy window (embedded blob or crypto
    constant table) is reported with state `isolated-high-entropy-region`
    and is NOT a whole-file packing signal.
    """
    out: list[dict] = []
    try:
        with zipfile.ZipFile(apk) as z:
            names = [n for n in z.namelist()
                     if (n.startswith("classes") and n.endswith(".dex"))
                     or (n.startswith("lib/") and n.endswith(".so"))]
            for n in names[:20]:
                try:
                    raw = z.read(n)
                except Exception:
                    continue
                cap = so_cap if n.startswith("lib/") else dex_cap
                rec = scan_region(raw[:cap])
                if rec.get("state") not in ("sustained-high-entropy",
                                            "isolated-high-entropy-region"):
                    continue
                rec["file"] = n
                rec["region_kind"] = classify_region_kind(n)
                out.append(rec)
    except zipfile.BadZipFile:
        pass
    return out
