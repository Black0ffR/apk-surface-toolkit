"""RT-01 — runtime-to-static correlation for normalized JSONL observations.

Parses captured trace events (no instrumentation is executed, no dynamic
tool is required) and associates them with static identities when — and
only when — evidence supports the mapping:

* artifact hashes are validated before any correlation, so a trace that
  belongs to a different APK/library version is never mapped;
* native runtime addresses are translated through the ELF-01 resolver
  using an explicitly supplied load bias (runtime address != ELF VA);
* exact static-identity matches and ELF address translations are
  ``confirmed``; everything else stays ``unresolved``;
* a static entity absent from the trace is reported as **not observed**,
  never as unreachable;
* malformed, duplicate and out-of-order events are tolerated and
  reported, and input is bounded (no silent truncation).

Event format follows plan §17.2.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile

from . import elf

DEFAULT_MAX_EVENTS = 100_000
DEFAULT_MAX_LINE_BYTES = 1 << 20
DEFAULT_MAX_EVIDENCE = 500

TRACE_LIMITATIONS = (
    "absence of an identity in the trace means not observed; it is not evidence of unreachability",
    "correlation requires the artifact hash to match; mismatched events are not mapped",
    "native mapping needs an explicit load bias; it is never assumed to be zero",
    "static correlation does not prove a call was executed at runtime",
)


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def event_id_for(raw: dict) -> str:
    """Stable id for raw events that carry none of their own."""
    return _sha256(_canonical(raw))[:16]


def normalize_event(raw: dict, *, source: str = "") -> dict:
    """Fill the §17.2 shape; unknown values stay explicit, never invented."""
    ev = {
        "event_id": str(raw.get("event_id") or event_id_for(raw)),
        "timestamp": str(raw.get("timestamp") or ""),
        "process": raw.get("process") or {},
        "artifact_sha256": str(raw.get("artifact_sha256") or ""),
        "layer": str(raw.get("layer") or "unknown"),
        "static_identity": raw.get("static_identity"),
        "runtime_identity": raw.get("runtime_identity"),
        "address_kind": raw.get("address_kind"),
        "mapping_status": str(raw.get("mapping_status") or "unresolved"),
        "source": str(raw.get("source") or source),
        "raw_event_sha256": _sha256(_canonical(raw)),
        "limitations": [],
    }
    for key in ("library", "library_sha256", "load_bias"):
        if key in raw:
            ev[key] = raw[key]
    return ev


def parse_trace(lines, *, source: str = "", max_events: int = DEFAULT_MAX_EVENTS,
                max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
                ) -> tuple[list[dict], list[dict]]:
    """Parse JSONL text lines -> (events, problems). Pure, bounded, no I/O.

    Problems are explicit records (malformed-json, not-object,
    line-too-long, duplicate-event, event-cap-reached); nothing is
    dropped silently.
    """
    events: list[dict] = []
    problems: list[dict] = []
    seen_ids: set[str] = set()
    last_ts = ""
    for n, raw_line in enumerate(lines or [], start=1):
        if len(raw_line) > max_line_bytes:
            problems.append({"line": n, "problem": "line-too-long",
                             "line_sha256": _sha256(raw_line),
                             "line_length": len(raw_line)})
            continue
        text = raw_line.strip()
        if not text:
            continue
        if len(events) >= max_events:
            problems.append({"line": n, "problem": "event-cap-reached",
                             "detail": f"stopped at max_events={max_events}"})
            break
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            problems.append({"line": n, "problem": "malformed-json",
                             "detail": type(exc).__name__,
                             "line_sha256": _sha256(raw_line)})
            continue
        if not isinstance(parsed, dict):
            problems.append({"line": n, "problem": "not-object",
                             "line_sha256": _sha256(raw_line)})
            continue
        event = normalize_event(parsed, source=source)
        if event["event_id"] in seen_ids:
            problems.append({"line": n, "problem": "duplicate-event",
                             "event_id": event["event_id"]})
            continue
        seen_ids.add(event["event_id"])
        ts = event["timestamp"]
        event["out_of_order"] = bool(ts and last_ts and ts < last_ts)
        if ts and ts > last_ts:
            last_ts = ts
        events.append(event)
    return events, problems


def check_artifacts(events: list[dict], *, apk_sha256: str = "",
                    libraries: dict | None = None) -> list[dict]:
    """Flag events traced from a different APK/library build.

    Annotates each event with ``artifact_match`` (True/False/None when no
    expectation is available) and returns problem records for mismatches.
    """
    expected_libs = {str(k): str(v) for k, v in (libraries or {}).items()}
    problems: list[dict] = []
    for ev in events:
        match = None
        got = str(ev.get("artifact_sha256") or "")
        if apk_sha256 and got:
            match = got == apk_sha256
            if not match:
                problems.append({"problem": "artifact-hash-mismatch",
                                 "event_id": ev["event_id"],
                                 "expected": apk_sha256, "got": got})
        ev["artifact_match"] = match
        lib_name = str(ev.get("library") or "")
        lib_expected = expected_libs.get(lib_name)
        lib_got = str(ev.get("library_sha256") or "")
        if lib_expected and lib_got and lib_expected != lib_got:
            problems.append({"problem": "library-hash-mismatch",
                             "event_id": ev["event_id"], "library": lib_name,
                             "expected": lib_expected, "got": lib_got})
            ev["artifact_match"] = False
    return problems


def _parse_address(value) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def map_native_events(events: list[dict], *, libraries) -> list[dict]:
    """Translate native runtime addresses via ELF-01 with explicit load bias.

    ``libraries``: records with ``name``, ``sha256``, ``abi``, ``segments``
    (elf.LoadSegment list) and ``load_bias``. Events whose artifact hash
    mismatched are left unresolved on purpose.
    """
    by_name = {str(lib.get("name", "")): lib for lib in (libraries or [])}
    for ev in events:
        if ev.get("layer") != "native" or ev.get("artifact_match") is False:
            if ev.get("artifact_match") is False:
                ev["limitations"].append("artifact hash mismatch; mapping skipped")
            continue
        addr = _parse_address(ev.get("runtime_identity"))
        if addr is None:
            ev["limitations"].append("runtime_identity is not a runtime address")
            continue
        ev["address_kind"] = ev.get("address_kind") or "runtime-address"
        lib = by_name.get(str(ev.get("library") or ""))
        if not lib:
            ev["limitations"].append("no library load record for this event")
            continue
        bias = lib.get("load_bias")
        if bias is None:
            ev["limitations"].append("load bias unknown; address not translated")
            continue
        va = elf.runtime_to_va(addr, int(bias))
        location = elf.describe_location(
            list(lib.get("segments") or []), va=va,
            library_sha256=str(lib.get("sha256") or ""),
            abi=str(lib.get("abi") or ""), load_bias=int(bias),
            runtime_address=addr)
        ev["location"] = location
        ev["mapping_status"] = location["mapping_status"]
        if (location["mapping_status"] in ("static-file-mapping", "memory-only")
                and location["elf_virtual_address"] is not None):
            ev["static_identity"] = (f"elf:{lib.get('name', '')}:"
                                     f"0x{location['elf_virtual_address']:x}")
            ev["static_mapping"] = {"kind": "confirmed",
                                    "method": "elf-address-translation"}
        else:
            ev["static_identity"] = None
    return events


def match_static_events(events: list[dict], *, static_identities) -> list[dict]:
    """Exact runtime-identity -> static-identity matches (java layer)."""
    known = {str(x) for x in (static_identities or [])}
    for ev in events:
        if ev.get("static_mapping"):
            continue
        rid = str(ev.get("runtime_identity") or "")
        if rid and rid in known and ev.get("artifact_match") is not False:
            ev["static_identity"] = rid
            ev["mapping_status"] = "static-identity-match"
            ev["static_mapping"] = {"kind": "confirmed",
                                    "method": "exact-static-identity-match"}
    return events


def correlate(events: list[dict], *, apk_sha256: str = "", libraries=None,
              static_identities=None, problems=None) -> dict:
    """Validate artifacts, map what evidence supports, summarize the rest."""
    artifact_problems = check_artifacts(
        events, apk_sha256=apk_sha256,
        libraries={lib.get("name"): lib.get("sha256") for lib in (libraries or [])})
    map_native_events(events, libraries=libraries)
    match_static_events(events, static_identities=static_identities)

    for ev in events:
        if "static_mapping" not in ev or ev["static_mapping"].get("kind") != "confirmed":
            ev["static_mapping"] = {"kind": "unresolved", "method": None}
            ev["static_identity"] = None

    unresolved = [
        {"event_id": ev["event_id"], "runtime_identity": ev.get("runtime_identity"),
         "layer": ev.get("layer"),
         "reasons": list(ev.get("limitations") or [])
         or ["no static identity match"]}
        for ev in events if ev["static_mapping"]["kind"] != "confirmed"
    ]
    seen = {ev["static_identity"] for ev in events
            if ev["static_mapping"]["kind"] == "confirmed" and ev["static_identity"]}
    known = {str(x) for x in (static_identities or [])}
    not_observed = sorted(known - seen)

    by_layer: dict[str, int] = {}
    for ev in events:
        layer = str(ev.get("layer") or "unknown")
        by_layer[layer] = by_layer.get(layer, 0) + 1
    duplicates = sum(1 for p in (problems or []) if p.get("problem") == "duplicate-event")
    malformed = sum(1 for p in (problems or [])
                    if p.get("problem") in ("malformed-json", "not-object",
                                            "line-too-long", "event-cap-reached"))
    return {
        "events": events,
        "unresolved": unresolved,
        "artifact_problems": artifact_problems,
        "not_observed": not_observed,
        "summary": {
            "events_observed": len(events),
            "by_layer": by_layer,
            "confirmed": sum(1 for ev in events
                             if ev["static_mapping"]["kind"] == "confirmed"),
            "unresolved": len(unresolved),
            "duplicates": duplicates,
            "parse_problems": malformed,
            "out_of_order": sum(1 for ev in events if ev.get("out_of_order")),
        },
        "limitations": list(TRACE_LIMITATIONS) + (
            ["duplicate events were ignored after the first occurrence"] if duplicates else []
        ) + (
            ["unparsed/truncated input records were skipped and reported"] if malformed else []
        ),
    }


# ------------------------------------------------ Batch I: CLI integration
_SMALI_CLASS_RE = re.compile(r"^\s*\.class\b.*?(L[^;]+;)")
_ESTABLISHED_JNI = ("confirmed_symbol_match", "supported_registration_match")


def load_trace(path: str, *, source: str = "",
               max_events: int = DEFAULT_MAX_EVENTS
               ) -> tuple[list[dict], list[dict]]:
    """Read a JSONL trace file -> (events, problems). Bounded, no surprises."""
    if not path or not os.path.isfile(path):
        return [], [{"problem": "trace-unreadable", "path": str(path),
                     "detail": "file not found"}]
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as exc:
        return [], [{"problem": "trace-unreadable", "path": str(path),
                     "detail": type(exc).__name__}]
    return parse_trace(lines, source=source or os.path.basename(path),
                       max_events=max_events)


def apply_event_load_biases(events: list[dict], libraries) -> int:
    """Adopt an observed load bias for a library when the event is trusted.

    Only fills a library that has no bias yet; an event flagged as coming
    from a different artifact is never used to fill.
    """
    by_name = {str(lib.get("name", "")): lib for lib in (libraries or [])}
    filled = 0
    for ev in events:
        if ev.get("layer") != "native" or ev.get("artifact_match") is False:
            continue
        if ev.get("load_bias") is None:
            continue
        lib = by_name.get(str(ev.get("library") or ""))
        if lib is None or lib.get("load_bias") is not None:
            continue
        lib["load_bias"] = ev["load_bias"]
        filled += 1
    return filled


def library_records_from_apk(apk_path: str, so_files
                             ) -> tuple[list[dict], list[dict]]:
    """Build ELF-01 load records for the APK's native libraries (read-only).

    Missing or malformed inputs become explicit problem records; a library
    that cannot be parsed never silently disappears from the picture.
    """
    records: list[dict] = []
    problems: list[dict] = []
    if not apk_path or not os.path.isfile(apk_path):
        return records, [{"problem": "apk-unreadable", "path": str(apk_path),
                          "detail": "file not found"}]
    try:
        with zipfile.ZipFile(apk_path) as z:
            for entry in so_files or []:
                try:
                    data = z.read(str(entry))
                except KeyError:
                    problems.append({"problem": "library-missing",
                                     "library": str(entry),
                                     "detail": "not present in apk"})
                    continue
                try:
                    image = elf.parse(data)
                except elf.ElfFormatError as exc:
                    problems.append({"problem": "elf-parse-failed",
                                     "library": str(entry),
                                     "detail": type(exc).__name__})
                    continue
                symbols, sym_errors = elf.parse_dynamic_symbols(data,
                                                                image=image)
                record = {
                    "name": os.path.basename(str(entry)),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "abi": elf.machine_name(image.machine),
                    "segments": list(image.loads),
                    "load_bias": None,
                    "symbols": symbols,
                }
                if sym_errors:
                    record["symbol_errors"] = list(sym_errors)
                records.append(record)
    except (OSError, zipfile.BadZipFile) as exc:
        return [], [{"problem": "apk-unreadable", "path": str(apk_path),
                     "detail": type(exc).__name__}]
    return records, problems


def _iter_smali(decoded: str):
    if not decoded or not os.path.isdir(decoded):
        return
    for name in sorted(os.listdir(decoded)):
        if not name.startswith("smali"):
            continue
        base = os.path.join(decoded, name)
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for fname in sorted(files):
                if fname.endswith(".smali"):
                    yield os.path.join(root, fname)


def static_identities_from_tree(decoded: str) -> list[str]:
    """Method signatures present in the decoded smali tree (callgraph format)."""
    identities: set[str] = set()
    for path in _iter_smali(decoded):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        cls = ""
        for line in text.splitlines():
            m = _SMALI_CLASS_RE.match(line)
            if m:
                cls = m.group(1)
                continue
            stripped = line.strip()
            if cls and stripped.startswith(".method") and "(" in stripped:
                token = stripped.split()[-1]
                if "(" in token:
                    identities.add(f"{cls}->{token}")
    return sorted(identities)


def jni_records_from_tree(decoded: str, libraries) -> list[dict]:
    """Correlate native declarations with each library's static evidence."""
    from . import jni as JNI
    decls: list[dict] = []
    for path in _iter_smali(decoded):
        rel = os.path.relpath(path, decoded)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        decls.extend(JNI.parse_native_declarations(text, file=rel))
    records: list[dict] = []
    for lib in libraries or []:
        records.extend(JNI.correlate(
            decls, library=str(lib.get("name", "")),
            library_sha256=str(lib.get("sha256") or ""),
            symbols=lib.get("symbols"),
            symbol_errors=lib.get("symbol_errors")))
    return records


def jni_identity_index(jni_records) -> dict:
    """Only established (confirmed/supported) JNI identities are linkable."""
    index: dict = {}
    for rec in jni_records or []:
        if rec.get("confidence") not in _ESTABLISHED_JNI:
            continue
        va = rec.get("elf_virtual_address")
        lib = str(rec.get("native_library") or "")
        if va is None or not lib:
            continue
        index.setdefault((lib, int(va)), rec)
    return index


def link_jni(events: list[dict], jni_records) -> int:
    """Attach a JNI java-method mapping to events with an established ELF VA."""
    index = jni_identity_index(jni_records)
    if not index:
        return 0
    linked = 0
    for ev in events:
        if ev.get("artifact_match") is False:
            continue
        loc = ev.get("location") or {}
        va = loc.get("elf_virtual_address")
        if va is None:
            continue
        rec = index.get((str(ev.get("library") or ""), int(va)))
        if rec is None:
            continue
        ev["jni_mapping"] = {
            "java_method": rec.get("java_method"),
            "native_symbol": rec.get("native_symbol"),
            "mapping_type": rec.get("mapping_type"),
            "confidence": rec.get("confidence"),
        }
        linked += 1
    return linked


def build_evidence_items(events, *, artifact_sha256: str = "",
                         max_items: int = DEFAULT_MAX_EVIDENCE
                         ) -> tuple[list[dict], bool]:
    """Runtime-event evidence items: observation separate from interpretation."""
    items: list[dict] = []
    truncated = False
    for ev in events or []:
        if len(items) >= max_items:
            truncated = True
            break
        layer = str(ev.get("layer") or "unknown")
        rid = ev.get("runtime_identity")
        confirmed = (ev.get("static_mapping") or {}).get("kind") == "confirmed"
        sid = ev.get("static_identity") if confirmed else None
        observation = f"runtime event observed: layer={layer} identity={rid}"
        if confirmed:
            interpretation = (f"matched static identity {sid} "
                              f"({ev.get('mapping_status') or 'confirmed'})")
        else:
            reasons = ("; ".join(ev.get("limitations") or [])
                       or "no static identity match")
            interpretation = f"unresolved: {reasons}"
        limitations = list(ev.get("limitations") or [])
        if not confirmed:
            limitations.append(
                "observed event without an established static identity; "
                "not a static finding")
        items.append({
            "id": f"runtime-{ev.get('event_id')}-{len(items)}",
            "type": "runtime_event",
            "confidence": "observed",
            "producer": "triagekit:runtime_trace",
            "event_id": ev.get("event_id"),
            "timestamp": str(ev.get("timestamp") or ""),
            "layer": layer,
            "runtime_identity": rid,
            "static_identity": sid,
            "source": str(ev.get("source") or ""),
            "artifact_sha256": (artifact_sha256
                                or str(ev.get("artifact_sha256") or "")),
            "excerpt_sha256": (ev.get("raw_event_sha256")
                               or _sha256(_canonical(ev))),
            "observation": observation,
            "interpretation": interpretation,
            "limitations": limitations,
        })
    return items, truncated


def build_report_block(correlation: dict, *, trace_source: str = "",
                       problems=(), jni_records=(), artifact_sha256: str = "",
                       max_evidence: int = DEFAULT_MAX_EVIDENCE) -> dict:
    """Assemble the additive ``runtime_trace`` report block."""
    events = correlation.get("events") or []
    items, truncated = build_evidence_items(
        events, artifact_sha256=artifact_sha256, max_items=max_evidence)
    limitations = list(correlation.get("limitations") or [])
    if truncated:
        limitations.append(
            f"evidence items truncated at max_evidence={max_evidence}")
    jni_links = [
        {"event_id": ev.get("event_id"), **dict(ev.get("jni_mapping") or {})}
        for ev in events if ev.get("jni_mapping")
    ]
    return {
        "trace": {"source": str(trace_source or ""),
                  "artifact_sha256": str(artifact_sha256 or "")},
        "summary": dict(correlation.get("summary") or {}),
        "events": events,
        "evidence_items": items,
        "unresolved": correlation.get("unresolved") or [],
        "not_observed": correlation.get("not_observed") or [],
        "artifact_problems": correlation.get("artifact_problems") or [],
        "parse_problems": list(problems or []),
        "jni_links": jni_links,
        "limitations": limitations,
    }


def attach_to_report(report: dict, block: dict) -> dict:
    """Add the runtime block without touching findings or analysis status."""
    report["runtime_trace"] = block
    return report
