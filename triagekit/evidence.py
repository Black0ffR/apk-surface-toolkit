"""EV-01 — report provenance and structured evidence (plan §11).

Additive layer over the legacy report schema:

* ``attach_report_metadata`` records ``schema_version``, ``run`` and
  ``artifact`` blocks, gives every finding a stable ``finding_id`` and
  derives ``evidence_items`` that keep observation and interpretation
  separate.
* Legacy fields are never modified. Redaction applies to presentation
  fields only (``run.command`` and ``evidence_items.observation``); the
  legacy ``evidence`` string keeps the source bytes so existing
  renderer/SARIF consumers are unchanged.
* ``finding_id`` excludes volatile run metadata (run_id, timestamps) and
  the artifact hash, so findings can be matched across runs and across
  APK versions (D3 diff semantics).

Evidence items reuse the Batch C record shapes instead of a parallel
schema: NA-01 keys (``file_offset``, ``source_artifact_sha256``,
``classification``, ``confidence``, ``validation``), ELF-01 address keys
(``elf_virtual_address``, ``runtime_address``) and the §19 confidence
vocabulary (JNI-01/NF-01 labels are mapped in, never copied verbatim).
"""
from __future__ import annotations

import hashlib
import os
import platform as _platform
import sys
import uuid

from . import carve

SCHEMA_VERSION = "2"

PRODUCER = "triagekit:analyzer"

# JNI-01 / NF-01 label -> §19 vocabulary (plan §11.3).
CONFIDENCE_MAP = {
    "confirmed_symbol_match": "supported",
    "supported_registration_match": "supported",
    "candidate_string_or_table_match": "candidate",
    "unresolved": "inconclusive",
}
CONFIDENCE_VOCAB = (
    "observed", "candidate", "supported", "verified", "inconclusive",
    "not_analysed", "partial", "refuted",
)

_SECRET_FLAGS = (
    "--token", "--password", "--passwd", "--api-key", "--apikey",
    "--secret", "--auth", "--header", "-H", "--keystore-password",
    "--store-pass", "--key-pass",
)

_ITEM_TYPES = ("smali_call", "manifest_attribute", "native_bytes",
               "runtime_event", "test_result", "analyzer_observation")

# parse_coverage problem counters (producers: callgraph build_stats). The
# informational totals (`methods`, `calls`) are never parser errors.
_PARSE_PROBLEM_KEYS = ("calls_legacy_fallback", "unparsed_invokes",
                       "malformed_methods")


def map_confidence(label) -> str:
    """Fold a producer label into the §19 vocabulary (default candidate)."""
    if not label:
        return "candidate"
    text = str(label)
    if text in CONFIDENCE_MAP:
        return CONFIDENCE_MAP[text]
    if text in CONFIDENCE_VOCAB:
        return text
    return "candidate"


def _redact_token(value: str) -> str:
    return carve.redact(value) if carve.looks_sensitive(value) else value


def sanitize_command(argv) -> list[str]:
    """Copy of argv safe for reports: secrets and home paths stripped."""
    out: list[str] = []
    home = os.path.expanduser("~")
    skip = False
    for raw in argv or []:
        s = str(raw)
        if home and s.startswith(home):
            s = "~" + s[len(home):]
        if skip:
            out.append("[redacted]")
            skip = False
            continue
        if s in _SECRET_FLAGS:
            out.append(s)
            skip = True
            continue
        flag_eq = next((fl for fl in _SECRET_FLAGS if s.startswith(fl + "=")), None)
        if flag_eq:
            out.append(flag_eq + "=[redacted]")
            continue
        attached = next((fl for fl in _SECRET_FLAGS
                         if not fl.startswith("--") and s.startswith(fl)
                         and len(s) > len(fl)), None)
        if attached:
            out.append(attached + "[redacted]")
            continue
        out.append(_redact_token(s))
    return out


# Detail keys that discriminate findings sharing rule/component/file/line:
# taint and reachability flows differ per sink/source line, native matches
# per file offset. Omitting them made distinct findings collide into the
# same finding_id (and a surviving finding could be reported as "removed,
# remediation confirmed" after list-order shifts).
_BASIS_DETAIL_KEYS = ("sink", "src_line", "file_offset")


def _identity_basis(finding: dict) -> str:
    detail = finding.get("detail") or {}
    line = detail.get("line")
    parts = [
        str(finding.get("rule", "")),
        str(finding.get("component", "")),
        str(finding.get("file", "")),
        "" if line is None else str(line),
    ]
    for key in _BASIS_DETAIL_KEYS:
        v = detail.get(key)
        if v is not None and v != "":
            parts.append(f"{key}={v}")
    return "|".join(parts)


def assign_finding_ids(findings: list[dict]) -> None:
    """Attach stable ids in place; duplicate bases get deterministic -N suffixes."""
    seen: dict[str, int] = {}
    for f in findings:
        digest = hashlib.sha256(
            _identity_basis(f).encode("utf-8", "replace")).hexdigest()[:16]
        n = seen.get(digest, 0)
        seen[digest] = n + 1
        f["finding_id"] = digest if n == 0 else f"{digest}-{n + 1}"


def _item_type(finding: dict) -> str:
    detail = finding.get("detail") or {}
    kind = str(finding.get("kind", ""))
    file = str(finding.get("file", "") or "")
    if ("file_offset" in detail or "encoding" in detail or "library" in detail
            or file.endswith((".so", ".dex", ".bin"))):
        return "native_bytes"
    if kind in ("smali-taint", "reachability") or file.endswith(".smali"):
        return "smali_call"
    if kind == "manifest":
        return "manifest_attribute"
    return "analyzer_observation"


def _location(finding: dict) -> dict:
    detail = finding.get("detail") or {}
    line = detail.get("line")
    return {
        "file": str(finding.get("file", "") or ""),
        "line_start": line,
        "line_end": line,
        "elf_file_offset": detail.get("file_offset"),
        "elf_virtual_address": detail.get("elf_virtual_address"),
        "runtime_address": detail.get("runtime_address"),
    }


def _limitations(finding: dict, analysis_status: str) -> list[str]:
    detail = finding.get("detail") or {}
    notes: list[str] = []
    if detail.get("truncated"):
        notes.append("hit list truncated at analysis limit")
    coverage = detail.get("parse_coverage")
    if isinstance(coverage, dict):
        bad = sum(coverage.get(k) or 0 for k in _PARSE_PROBLEM_KEYS)
        if bad:
            notes.append(f"parser coverage incomplete ({bad} skipped/malformed)")
        truncated_files = coverage.get("files_truncated")
        if isinstance(truncated_files, int) and truncated_files > 0:
            notes.append(f"{truncated_files} file(s) truncated at the read cap")
    validation = detail.get("validation")
    if validation == "not_runtime_verified":
        notes.append("not runtime verified")
    if finding.get("static_only"):
        notes.append("static-only; runtime verification not performed")
    if analysis_status and analysis_status != "complete":
        notes.append(f"analysis run status: {analysis_status}")
    return notes


def build_evidence_items(finding: dict, *, artifact_sha256: str = "",
                         analysis_status: str = "") -> list[dict]:
    """One derived item per finding from legacy fields + Batch C detail keys."""
    detail = finding.get("detail") or {}
    evidence_text = str(finding.get("evidence", "") or "")
    observation = _redact_token(evidence_text) if evidence_text else ""
    excerpt = (hashlib.sha256(evidence_text.encode("utf-8", "replace")).hexdigest()
               if evidence_text else None)
    artifact = str(detail.get("source_artifact_sha256") or artifact_sha256 or "")
    return [{
        "type": _item_type(finding),
        "artifact_sha256": artifact,
        "location": _location(finding),
        "excerpt_sha256": excerpt,
        "observation": observation,
        "interpretation": str(finding.get("title", "") or ""),
        "confidence": map_confidence(
            detail.get("confidence") or finding.get("confidence")),
        "limitations": _limitations(finding, analysis_status),
        "producer": PRODUCER,
    }]


def attach_report_metadata(report: dict, *, started_at: str,
                           completed_at: str, command=None) -> dict:
    """Add schema_version/run/artifact blocks, finding ids and evidence items.

    Idempotent: recomputation from the same inputs yields identical
    outputs. Legacy fields are left byte-identical.
    """
    report["schema_version"] = SCHEMA_VERSION
    report["run"] = {
        "run_id": uuid.uuid4().hex[:16],
        "started_at": started_at,
        "completed_at": completed_at,
        "tool_version": str(report.get("version", "")),
        "python_version": _platform.python_version(),
        "platform": sys.platform,
        "command": sanitize_command(command),
    }
    report["artifact"] = {
        "path_label": os.path.basename(str(report.get("apk_path", "") or "")),
        "sha256": str(report.get("apk_sha256", "") or ""),
        "size_bytes": report.get("size"),
    }
    findings = report.get("findings") or []
    analysis_status = str((report.get("analysis") or {}).get("status", ""))
    for f in findings:
        f["evidence_items"] = build_evidence_items(
            f, artifact_sha256=report["artifact"]["sha256"],
            analysis_status=analysis_status)
    assign_finding_ids(findings)
    return report
