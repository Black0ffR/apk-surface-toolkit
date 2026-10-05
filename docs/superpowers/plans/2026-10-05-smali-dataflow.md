# Smali Dataflow Tracker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build intra-method smali register taint tracking that connects attacker-controlled Intent input to dangerous sinks.

**Architecture:** New stdlib-only module `triagekit/taint_smali.py` splits decoded `.smali` files into `.method` blocks, taints registers from source invokes, and reports tainted registers reaching sink invokes. Wired into `analyzer.analyse()` beside `check_regex` with the same vendor-skip, cap, and BLIND-0002 honesty behavior.

**Tech Stack:** Python 3 stdlib only (`os`, `re`); no new dependencies; Termux/phone CPU budget applies.

**Spec:** `docs/superpowers/specs/2026-10-05-smali-dataflow-design.md`

## Global Constraints

- Python 3 stdlib only — no new dependencies.
- Every subprocess uses argv lists, never shell strings (see `triagekit/utils.py:run`).
- Vendor dirs skipped by default (`smali/android`, `smali/androidx`, `smali/com/google`, `smali/com/googlecode`, `smali/kotlin`, `smali/kotlinx`, `smali/okhttp3`, `smali/okio`, `smali/javax`, `smali/org/apache`, `smali/org/json`, `smali/dagger`, `smali/com/squareup`, `smali/io/reactivex`) unless rule sets `params.include_vendor=true`.
- Findings carry `detail.truncated=true` + `[truncated at N hits]` when capped — never silent truncation.
- Packed or manifest-only samples skip code analysis and count skipped rules in BLIND-0002.
- Full InsecureBankv2 run must finish inside the 280s on-phone budget.

---

### Task 1: `taint_smali.py` core module

**Files:**
- Create: `triagekit/taint_smali.py`
- Test: `/data/data/com.termux/files/usr/tmp/taint_fixture/run.py` (throwaway fixture, not committed)

**Interfaces:**
- Consumes: `triagekit/rules.py:Rule` (uses `r.params.get("sources")`, `r.params.get("sinks")`, `r.params.get("cap", 15)`, `r.params.get("include_vendor", False)`), `R.finding(rule, file=..., evidence=..., extra=...)`
- Produces: `scan(decoded: str, rules: list[Rule], limit_default: int = 15) -> list[dict]` used by Task 2.

- [ ] **Step 1: Write the failing fixture test**

```python
# /data/data/com.termux/files/usr/tmp/taint_fixture/run.py
import os, sys, tempfile, textwrap
sys.path.insert(0, "/data/data/com.termux/files/home/apk-surface-toolkit")
from triagekit import rules as R, taint_smali as T

FLOW = textwrap.dedent("""\
    .class public Lcom/t/Vuln;
    .super Ljava/lang/Object;
    .method public onCreate(Landroid/os/Bundle;)V
        .locals 3
        invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;
        move-result-object v1
        move-object v2, v1
        invoke-virtual {p0, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
        return-void
    .end method
    """)
CLEAN = textwrap.dedent("""\
    .class public Lcom/t/Clean;
    .super Ljava/lang/Object;
    .method public go()V
        .locals 2
        const-string v0, "https://example.com/static"
        invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
        return-void
    .end method
    """)
XMOD = textwrap.dedent("""\
    .class public Lcom/t/Split;
    .super Ljava/lang/Object;
    .method public a(Landroid/content/Intent;)V
        .locals 1
        invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
        move-result-object v0
        return-void
    .end method
    .method public b()V
        .locals 1
        invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
        return-void
    .end method
    """)
TDIR = tempfile.mkdtemp()
for name, body in (("Vuln.smali", FLOW), ("Clean.smali", CLEAN), ("Split.smali", XMOD)):
    open(os.path.join(TDIR, name), "w").write(body)
r = R.Rule({"id": "T-DF", "title": "t", "kind": "smali-taint", "severity": "high",
            "params": {"sources": ["getIntent", "getData"],
                       "sinks": ["loadUrl"]}}, "t")
out = T.scan(TDIR, [r])
got = {(f["file"], f["detail"]["sink"]) for f in out}
assert ("Vuln.smali", "loadUrl") in {(f, s) for f, s in got}, f"direct flow missed: {out}"
assert not [f for f in out if f["file"] == "Clean.smali"], f"clean fired: {out}"
assert not [f for f in out if f["file"] == "Split.smali"], f"cross-method fired in v1: {out}"
print("TAINT FIXTURE PASS", len(out))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 /data/data/com.termux/files/usr/tmp/taint_fixture/run.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'triagekit.taint_smali'`

- [ ] **Step 3: Write minimal implementation**

```python
# triagekit/taint_smali.py
"""Intra-method smali register taint: Intent sources -> dangerous sinks."""
from __future__ import annotations

import os
import re

from . import rules as R
from .analyzer import VENDOR_PREFIXES

_DEFAULT_SOURCES = ("getIntent", "getData", "getStringExtra",
                    "getParcelableExtra", "getSerializableExtra")
_DEFAULT_SINKS = ("loadUrl", "addJavascriptInterface", "startActivity",
                  "startService", "sendBroadcast", "setClass")

_MOVE_RE = re.compile(r"^\s*move(?:-result|-object|-wide|-result-object)?\s+(v\d+|p\d+)", re.I)
_MOVE_RESULT_RE = re.compile(r"^\s*move-result(?:-object|-wide)?\s+(v\d+|p\d+)", re.I)
_METHOD_RE = re.compile(r"^\s*\.method\b(.*)$", re.I)
_END_METHOD_RE = re.compile(r"^\s*\.end\s+method", re.I)
_INVOKE_RE = re.compile(r"^\s*invoke-\S+\s*\{([^}]*)\},\s*(\S+)->(\S+)\(", re.I)


def _regs(arglist: str) -> list[str]:
    return [a.strip() for a in arglist.split(",") if a.strip().startswith(("v", "p"))]


def _scan_method(lines: list[str], src_pat: re.Pattern, sink_pat: re.Pattern) -> list[dict]:
    """Return [{src_line, sink_line, sink, reg, path}] for one .method body."""
    tainted: dict[str, dict] = {}
    pending_src: dict | None = None
    hits: list[dict] = []
    for i, line in enumerate(lines):
        m = _INVOKE_RE.match(line)
        if m:
            args, owner, method = m.groups()
            regs = _regs(args)
            if src_pat.search(method) or src_pat.search(owner):
                pending_src = {"line": i, "method": method.strip()}
                continue
            if sink_pat.search(method):
                for reg in regs:
                    if reg in tainted:
                        t = tainted[reg]
                        hits.append({"src_line": t["line"],
                                     "src_method": t["method"],
                                     "sink_line": i, "sink": method.strip(),
                                     "reg": reg,
                                     "path": t.get("path", []) + [reg]})
                        break
            continue
        m = _MOVE_RESULT_RE.match(line)
        if m and pending_src is not None:
            reg = m.group(1)
            tainted[reg] = {"line": pending_src["line"],
                            "method": pending_src["method"],
                            "path": [reg]}
            pending_src = None
            continue
        m = _MOVE_RE.match(line)
        if m:
            parts = re.split(r"[,\s]+", line.strip())
            dst = parts[-1].rstrip(",;") if parts else ""
            srcs = [p.rstrip(",;") for p in parts[1:-1]]
            hit = [s for s in srcs if s in tainted]
            if dst and hit:
                tainted[dst] = {"line": tainted[hit[0]]["line"],
                                "method": tainted[hit[0]]["method"],
                                "path": tainted[hit[0]].get("path", []) + [dst]}
    return hits


def scan(decoded: str, rules: list, limit_default: int = 15) -> list[dict]:
    out: list[dict] = []
    if not decoded or not os.path.isdir(decoded):
        return out
    for r in rules:
        sources = r.params.get("sources", list(_DEFAULT_SOURCES))
        sinks = r.params.get("sinks", list(_DEFAULT_SINKS))
        cap = int(r.params.get("cap", limit_default))
        include_vendor = bool(r.params.get("include_vendor", False))
        try:
            src_pat = re.compile("|".join(sources))
            sink_pat = re.compile("|".join(sinks))
        except re.error as e:
            out.append(R.finding(r, evidence=f"bad taint pattern: {e}"))
            continue
        base = os.path.join(decoded, r.params.get("root", "."))
        if not os.path.isdir(base):
            continue
        hits = 0
        start = len(out)
        for dirpath, dirnames, files in os.walk(base):
            rel = os.path.relpath(dirpath, base)
            if not include_vendor and any(
                    rel == vp or rel.startswith(vp + os.sep)
                    for vp in VENDOR_PREFIXES):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fn in files:
                if not fn.endswith(".smali"):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        content = fh.read(500_000)
                except OSError:
                    continue
                block: list[str] = []
                in_method = False
                sig = ""
                for raw in content.splitlines():
                    if _METHOD_RE.match(raw):
                        in_method = True
                        block = [raw]
                        sig = raw.strip()[:120]
                        continue
                    if in_method:
                        block.append(raw)
                    if in_method and _END_METHOD_RE.match(raw):
                        in_method = False
                        for h in _scan_method(block, src_pat, sink_pat):
                            relp = os.path.relpath(p, decoded)
                            out.append(R.finding(
                                r, file=relp,
                                evidence=(f"{relp}:{sig}: tainted {h['reg']} "
                                          f"from {h['src_method']} reaches "
                                          f"{h['sink']}"),
                                extra={"method": sig, "sink": h["sink"],
                                       "reg": h["reg"],
                                       "src_method": h["src_method"]}))
                            hits += 1
                            if hits >= cap:
                                break
                    if hits >= cap:
                        break
                if hits >= cap:
                    break
            if hits >= cap:
                break
        if hits >= cap:
            for i in range(start, len(out)):
                det = out[i].setdefault("detail", {})
                det["truncated"] = True
                det["limit"] = cap
            out[-1]["evidence"] += f" [truncated at {cap} hits]"
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 /data/data/com.termux/files/usr/tmp/taint_fixture/run.py`
Expected: PASS with `TAINT FIXTURE PASS 1`

- [ ] **Step 5: Commit**

```bash
git add triagekit/taint_smali.py
git -c user.name="Black0ffR" -c user.email="Black0ffR@users.noreply.github.com" commit -m "feat: intra-method smali taint tracker"
```

### Task 2: Analyzer wiring

**Files:**
- Modify: `triagekit/analyzer.py:1-15` (import `taint_smali`), `triagekit/analyzer.py:627-643` (scan call + BLIND-0002 count)

**Interfaces:**
- Consumes: Task 1 `taint_smali.scan(decoded, rules) -> list[dict]`; existing `R.load_dir` rules with `kind == "smali-taint"`.
- Produces: findings list extended in `analyse()`; `rule_count` in `analysis.json` grows automatically via `R.load_dir`.

- [ ] **Step 1: Write the failing wiring test**

```python
# /data/data/com.termux/files/usr/tmp/taint_fixture/wire.py
import sys
sys.path.insert(0, "/data/data/com.termux/files/home/apk-surface-toolkit")
from triagekit import analyzer as A
import inspect
src = inspect.getsource(A.analyse)
assert "taint_smali" in src, "analyse() does not call taint_smali"
assert "smali-taint" in src, "analyse() does not select kind smali-taint"
print("WIRE PASS")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 /data/data/com.termux/files/usr/tmp/taint_fixture/wire.py`
Expected: FAIL with `AssertionError: analyse() does not call taint_smali`

- [ ] **Step 3: Write minimal implementation**

```python
# top of triagekit/analyzer.py beside other relative imports:
from . import apktools, manifest as mf, rules as R, taint_smali as TS
```

```python
# inside analyse(), in the do_regex block after the check_regex call:
            findings += TS.scan(decode_dir, [r for r in all_rules if r.kind == "smali-taint"])
```

```python
# BLIND-0002 evidence line becomes:
                "evidence": f"{len([r for r in all_rules if r.kind in ('regex', 'smali-taint')])} code rules not run "
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 /data/data/com.termux/files/usr/tmp/taint_fixture/wire.py && python3 /data/data/com.termux/files/usr/tmp/taint_fixture/run.py`
Expected: PASS `WIRE PASS` then PASS `TAINT FIXTURE PASS 1`

- [ ] **Step 5: Commit**

```bash
git add triagekit/analyzer.py
git -c user.name="Black0ffR" -c user.email="Black0ffR@users.noreply.github.com" commit -m "feat: wire smali-taint scan into analyse()"
```

### Task 3: Rules AS-0033 / AS-0034

**Files:**
- Create: `rules/AS-0033-dataflow-webview.json`, `rules/AS-0034-dataflow-redirection.json`

**Interfaces:**
- Consumes: Task 1 params contract (`sources`, `sinks`, `cap`, `root`, `include_vendor`).
- Produces: rule IDs referenced in Task 4 verification counts.

- [ ] **Step 1: Write the failing load test**

```python
# /data/data/com.termux/files/usr/tmp/taint_fixture/rules.py
import sys
sys.path.insert(0, "/data/data/com.termux/files/home/apk-surface-toolkit")
from triagekit import rules as R
rs, errs = R.load_dir("rules")
by_id = {r.id: r for r in rs}
assert not errs, errs
for rid in ("AS-0033", "AS-0034"):
    assert rid in by_id, f"{rid} missing"
    assert by_id[rid].kind == "smali-taint", by_id[rid].kind
print("RULES PASS", len(rs))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 /data/data/com.termux/files/usr/tmp/taint_fixture/rules.py`
Expected: FAIL with `AssertionError: AS-0033 missing`

- [ ] **Step 3: Write minimal implementation**

```json
// rules/AS-0033-dataflow-webview.json
{
  "id": "AS-0033",
  "title": "Attacker input reaches WebView sink",
  "kind": "smali-taint",
  "check": "smali_taint",
  "severity": "high",
  "maswe": "MASWE-0035",
  "tags": ["webview", "dataflow"],
  "params": {
    "sources": ["getIntent", "getData", "getStringExtra", "getParcelableExtra", "getSerializableExtra"],
    "sinks": ["loadUrl", "addJavascriptInterface"],
    "cap": 15
  },
  "recommendation": "Validate the URI/origin before loading; disable file access unless needed.",
  "repro": "am start -W -a android.intent.action.VIEW -d \"<scheme>://<host>/poc\" {package}"
}
```

```json
// rules/AS-0034-dataflow-redirection.json
{
  "id": "AS-0034",
  "title": "Attacker input drives component navigation",
  "kind": "smali-taint",
  "check": "smali_taint",
  "severity": "high",
  "maswe": "MASWE-0032",
  "tags": ["ipc", "intent-redirection", "dataflow"],
  "params": {
    "sources": ["getIntent", "getParcelableExtra", "getSerializableExtra", "getStringExtra", "getData"],
    "sinks": ["startActivity", "startService", "sendBroadcast", "setClass"],
    "cap": 15
  },
  "recommendation": "Never let an inbound extra select the target component/action. Allow-list destinations.",
  "repro": "am start -n {package}/{component} --es redirect <internal>"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 /data/data/com.termux/files/usr/tmp/taint_fixture/rules.py`
Expected: PASS with `RULES PASS 34`

- [ ] **Step 5: Commit**

```bash
git add rules/AS-0033-dataflow-webview.json rules/AS-0034-dataflow-redirection.json
git -c user.name="Black0ffR" -c user.email="Black0ffR@users.noreply.github.com" commit -m "feat: AS-0033/AS-0034 smali-taint rules"
```

### Task 4: Probes + full verification + push

**Files:**
- Modify: `triagekit/tests_gen.py` (reuse existing deeplink/intent emitters per taint finding — no new emitter functions, 6 lines max)
- Test: InsecureBankv2 full run + Task 1 fixture re-run

**Interfaces:**
- Consumes: Tasks 1–3 findings (`detail.sink`, `detail.method`, `file`).
- Produces: pushed `main` with updated rule count.

- [ ] **Step 1: Write the failing probe test**

```python
# /data/data/com.termux/files/usr/tmp/taint_fixture/probes.py
import sys
sys.path.insert(0, "/data/data/com.termux/files/home/apk-surface-toolkit")
from triagekit import tests_gen as G
import inspect
src = inspect.getsource(G.generate)
assert "taint" in src.lower() or "loadUrl" in src, "tests_gen has no taint path"
print("PROBES PASS")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 /data/data/com.termux/files/usr/tmp/taint_fixture/probes.py`
Expected: FAIL with `AssertionError: tests_gen has no taint path`

- [ ] **Step 3: Write minimal implementation**

```python
# in triagekit/tests_gen.py generate(), after the deep-links block, add:
    taints = [f for f in (r.get("findings") or [])
              if f.get("rule") in ("AS-0033", "AS-0034")]
    if taints:
        L.append('# ------------------------------------------------- taint sinks (verify live)')
        for f in taints[:10]:
            det = f.get("detail") or {}
            L.append(f'# {f["rule"]} {det.get("sink", "")} via {det.get("reg", "")} in {det.get("method", "")[:80]}')
            L.append(f'# file: {f.get("file", "")}')
        L.append("")
```

- [ ] **Step 4: Run full verification**

Run: `python3 /data/data/com.termux/files/usr/tmp/taint_fixture/run.py && rm -rf /data/data/com.termux/files/usr/tmp/dfcheck && timeout 280 python3 bin/apk-surface analyze --out /data/data/com.termux/files/usr/tmp/dfcheck /data/data/com.termux/files/usr/tmp/apktest/insecure.apk`
Expected: `TAINT FIXTURE PASS 1`, full run RC=1 within budget, 34 rules loaded, no `ModuleNotFoundError`, no `NameError`.

- [ ] **Step 5: Commit and push**

```bash
git add triagekit/tests_gen.py
git -c user.name="Black0ffR" -c user.email="Black0ffR@users.noreply.github.com" commit -m "feat: taint sink probes in tests.sh"
git push
```
Expected: `main -> main`, `git log --oneline -3` shows taint commits on top.
