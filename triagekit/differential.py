"""DT-01: deterministic differential-testing harness (plan §16).

Compares an explicitly supplied reference function against a candidate
function over a bounded, deterministic corpus. Static-analysis safety:
this module never spawns subprocesses, never loads native libraries,
never executes APKs, and never touches the network. Callables are pure
in-process Python functions chosen by the caller.

A finite-corpus agreement is reported as "matches-tested-corpus"; it is
never labeled as full equivalence. An empty corpus is reported as
"inconclusive-empty-corpus" — no cases means no comparison happened.
Oversized inputs are skipped, not
truncated, and skipped/failed/crashed cases are never counted as
mismatches or matches.

Recorded evidence avoids plaintext input storage: inputs and outputs are
identified by SHA-256 (plus length) only, unless the caller minimizes a
mismatch and chooses to store the bytes themselves.
"""

from __future__ import annotations

import hashlib
import random
import signal
import threading
import time

DEFAULT_MAX_CASE_BYTES = 1_000_000


class _TimeoutError(Exception):
    pass


def _on_alarm(signum, frame):  # pragma: no cover - signal trampoline
    raise _TimeoutError()


_TIMEOUT_OK = (
    hasattr(signal, "SIGALRM")
    and hasattr(signal, "setitimer")
    and threading.current_thread() is threading.main_thread()
)


def _as_bytes(data) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"cases must be bytes-like, got {type(data).__name__}")


def _output_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(
        f"callable returned {type(value).__name__}, expected bytes")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _call_value(func, data: bytes, seconds) -> bytes:
    """Invoke one pure callable, optionally under a wall-clock bound."""
    if seconds is None:
        return _output_bytes(func(data))
    old = signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return _output_bytes(func(data))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _run_outcome(phase: str, func, data: bytes, seconds):
    """Return (output_or_None, error_or_None, elapsed_ms)."""
    start = time.perf_counter()
    try:
        out = _call_value(func, data, seconds)
        elapsed = round((time.perf_counter() - start) * 1000.0, 3)
        return out, None, elapsed
    except _TimeoutError:
        elapsed = round((time.perf_counter() - start) * 1000.0, 3)
        return None, {"phase": phase, "type": "timeout",
                      "message": f"exceeded max_seconds_per_case={seconds}"}, \
            elapsed
    except Exception as exc:  # noqa: BLE001 - recorded as evidence
        elapsed = round((time.perf_counter() - start) * 1000.0, 3)
        return None, {"phase": phase, "type": type(exc).__name__,
                      "message": str(exc)[:200]}, elapsed


def minimize_mismatch(data: bytes, reference, candidate, *,
                      max_rounds: int = 64,
                      max_seconds_per_case=None) -> tuple[bytes, int]:
    """Shrink `data` while the reference/candidate outputs still differ.

    Returns `(minimized_bytes, rounds)`. The bytes are handed back to the
    caller for storage decisions; the harness itself records hashes only.
    """
    data = _as_bytes(data)
    if max_rounds <= 0:
        raise ValueError("max_rounds must be positive")

    def reproduces(chunk: bytes) -> bool:
        try:
            ref_out = _call_value(reference, chunk, max_seconds_per_case)
            cand_out = _call_value(candidate, chunk, max_seconds_per_case)
        except Exception:  # noqa: BLE001 - unreproducible => stop shrinking
            return False
        return ref_out != cand_out

    if data and not reproduces(data):
        return data, 0
    if not data:
        return data, 0

    current = data
    rounds = 0
    while rounds < max_rounds and len(current) > 0:
        n = len(current)
        progressed = False
        for keep in (current[n // 2:], current[:n // 2]):
            if len(keep) < n and reproduces(keep):
                current = keep
                rounds += 1
                progressed = True
                break
        if not progressed:
            break
    return current, rounds


def compare_outputs(cases, reference, candidate, *,
                    max_case_bytes: int = DEFAULT_MAX_CASE_BYTES,
                    max_seconds_per_case: float | None = None,
                    minimize: bool = True,
                    max_minimize_rounds: int = 64) -> list[dict]:
    """Compare reference vs candidate over a deterministic case list.

    Limits are validated and enforced before any callable runs. Case
    identity is `index-input_sha256` and excludes volatile timing data.
    """
    if max_case_bytes <= 0:
        raise ValueError("max_case_bytes must be positive")
    if max_seconds_per_case is not None:
        if max_seconds_per_case <= 0:
            raise ValueError("max_seconds_per_case must be positive")
        if not _TIMEOUT_OK:
            raise RuntimeError(
                "execution-time bounds are unavailable on this platform")
    if max_minimize_rounds <= 0:
        raise ValueError("max_minimize_rounds must be positive")

    results: list[dict] = []
    for index, raw in enumerate(cases):
        data = _as_bytes(raw)
        digest = _sha(data)
        base = {
            "case_id": f"{index}-{digest}",
            "index": index,
            "input_sha256": digest,
            "input_length": len(data),
        }
        if len(data) > max_case_bytes:
            results.append({
                **base,
                "status": "skipped",
                "equal": None,
                "reference_sha256": None,
                "candidate_sha256": None,
                "elapsed_ms": {"reference": None, "candidate": None,
                               "total": None},
                "error": None,
                "minimized": None,
                "reason": (f"input exceeds max_case_bytes "
                           f"({len(data)} > {max_case_bytes})"),
            })
            continue

        started = time.perf_counter()
        ref_out, ref_err, ref_ms = _run_outcome(
            "reference", reference, data, max_seconds_per_case)
        if ref_err is not None:
            results.append({
                **base,
                "status": "failure",
                "equal": None,
                "reference_sha256": None,
                "candidate_sha256": None,
                "elapsed_ms": {"reference": ref_ms, "candidate": None,
                               "total": round(
                                   (time.perf_counter() - started) * 1000.0,
                                   3)},
                "error": ref_err,
                "minimized": None,
                "reason": None,
            })
            continue

        cand_out, cand_err, cand_ms = _run_outcome(
            "candidate", candidate, data, max_seconds_per_case)
        total_ms = round((time.perf_counter() - started) * 1000.0, 3)
        if cand_err is not None:
            results.append({
                **base,
                "status": "failure",
                "equal": None,
                "reference_sha256": _sha(ref_out),
                "candidate_sha256": None,
                "elapsed_ms": {"reference": ref_ms, "candidate": cand_ms,
                               "total": total_ms},
                "error": cand_err,
                "minimized": None,
                "reason": None,
            })
            continue

        equal = ref_out == cand_out
        record = {
            **base,
            "status": "match" if equal else "mismatch",
            "equal": equal,
            "reference_sha256": _sha(ref_out),
            "candidate_sha256": _sha(cand_out),
            "elapsed_ms": {"reference": ref_ms, "candidate": cand_ms,
                           "total": total_ms},
            "error": None,
            "minimized": None,
            "reason": None,
        }
        if not equal and minimize:
            small, rounds = minimize_mismatch(
                data, reference, candidate,
                max_rounds=max_minimize_rounds,
                max_seconds_per_case=max_seconds_per_case)
            record["minimized"] = {
                "input_sha256": _sha(small),
                "input_length": len(small),
                "rounds": rounds,
            }
        results.append(record)
    return results


def equivalence_summary(results: list[dict], *, reference_label: str = "",
                        candidate_label: str = "",
                        corpus_label: str = "") -> dict:
    """Summarize a run without ever claiming full equivalence."""
    counts = {"total": len(results), "match": 0, "mismatch": 0,
              "failure": 0, "skipped": 0}
    for record in results:
        status = record.get("status")
        if status in counts:
            counts[status] += 1
    if counts["total"] == 0:
        conclusion = "inconclusive-empty-corpus"
    elif counts["failure"] or counts["skipped"]:
        conclusion = "incomplete-corpus"
    elif counts["mismatch"]:
        conclusion = "divergences-found"
    else:
        conclusion = "matches-tested-corpus"
    return {
        "reference_label": reference_label,
        "candidate_label": candidate_label,
        "corpus_label": corpus_label,
        "counts": counts,
        "case_ids": [r["case_id"] for r in results],
        "conclusion": conclusion,
        "limitations": [
            "conclusion covers only the tested corpus; it is not proof of "
            "full equivalence",
            "crashes, timeouts, and skipped inputs are test results, not "
            "security conclusions",
            "mismatches must be reproduced before being reported as defects",
        ],
    }


def default_corpus(*, seed: int = 0, block: int = 16,
                   max_long: int = 4096) -> list[bytes]:
    """Deterministic corpus per plan §16.4. Same seed => same bytes."""
    if block <= 0 or max_long <= 0:
        raise ValueError("block and max_long must be positive")
    rnd = random.Random(seed)
    return [
        b"",
        b"\x00",
        b"\xff",
        b"\x01",
        b"\x00" * block,
        b"\xff" * block,
        b"A" * (block - 1),
        b"A" * block,
        b"A" * (block + 1),
        b"AB" * block,
        bytes(range(256)),
        b"\x80\x81\xfe\xff",
        b"\x7f\x80\x7f\x80",
        b"\x00" * max_long,
        b"\xff" * (max_long - 1),
        rnd.randbytes(max(16, block * 4)),
        rnd.randbytes(7),
    ]
