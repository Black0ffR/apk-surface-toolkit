# apk-surface-toolkit

Static attack-surface mapping for Android APKs. Termux-first, stdlib-only Python. Every external binary is optional and degrades gracefully.

Two tools:

- **`bin/apk-surface`** — decode → parse manifest → run 38 JSON rules (`AS-0001`–`AS-0038`: manifest, regex, smali-taint, reachability) → `analysis.json` + `report.md` + emit-only `tests.sh` (`analyze|query|diff|trace|doctor`). The authoritative loaded-rule count is reported by the analyzer (`rule_count` / `rule_inventory` in `analysis.json`); file count and loaded count differ when a rule file fails validation.
- **`capdoctor`** — read-only device capability report (no network, no root prompt unless `--deep`)

## Quick start

```bash
pkg install apktool aapt2 apksigner openjdk-21
# apkid optional (packer heuristics); fails to build on Termux — skipped gracefully

./bin/apk-surface doctor
./bin/apk-surface analyze app.apk -o ./out
./bin/apk-surface query ./out/<sha12> --type activity
./bin/apk-surface trace ./capture.jsonl -a ./out/<sha12> --json
capdoctor
capdoctor --tools
```

Install to PATH:

```bash
install -m755 capdoctor "$PREFIX/bin/"
printf '#!/bin/sh\nexec python3 "$HOME/apk-surface-toolkit/bin/apk-surface" "$@"\n' > "$PREFIX/bin/apk-surface"
chmod 755 "$PREFIX/bin/apk-surface"
```

## Verified

- InsecureBankv2.apk (3.4 MB): 13 components · 7 exported · 3 high / 6 medium / 26 low / 1 info (exported comps, provider, debuggable, JS bridge). `decode ok:True manifest_only:False`, exit 1 on high findings, 3 on incomplete decode.
- Blind-spot honesty: missing apktool → `MANIFEST NOT ANALYSED` + `BLIND-0003`, never a silent clean. Fallback tree stamped `.manifest-only` so reuse can't masquerade as full decode. Regex hits capped at 25 with `truncated:true` + `[truncated at 25 hits]`.
- `capdoctor` reports `unknown (findmnt unavailable)` instead of guessing `exec`.

## Layout

```
bin/apk-surface  thin launcher (needs triagekit/ beside it)
capdoctor        standalone, stdlib only
triagekit/      analyzer, apktools, axml (built-in binary manifest parser),
                manifest, rules, report, tests_gen (emit-only), diff, utils,
                elf, entropy, jni, callgraph, native_flow, taint_smali, evidence,
                runtime_trace
rules/AS-*.json 38 rules (25 manifest + 10 regex + 2 smali-taint + 1 reachability) + platform_permissions.txt
```

## Analysis scope and limitations

- Static analysis only. Every finding is a hypothesis until reproduced at runtime.
- Smali taint findings are `candidate` flows from a bounded intra-method CFG fixed-point register scan; interprocedural summaries are opt-in per rule and bounded. Unresolved calls, ambiguous method identities, recursive/incomplete summaries and unverifiable sanitizers are reported as gaps (an `interprocedural gaps:` entry in the stage record plus counters on the finding) — a sanitizer is only honored when its full body resolves, and anything unresolved stays `partial`, never clean. Known precision limit: a sanitizer used *inside* a helper body is not propagated through that helper's summary, so a flow sanitized only within the helper is over-reported as a candidate (false positive); sanitizer handling never removes a flow that reached a sink, so this cannot hide a real one.
- Native evidence flow: `.so` files are parsed read-only (ELF header, segments, dynamic symbols); ELF32 and ELF64 program headers are unpacked with their distinct field orders (they are not interchangeable — an ELF64 header must not be read with the ELF32 layout). ELF location mapping translates runtime addresses through segments with an explicit load bias that is never assumed to be zero. Direct-call extraction accepts both bare and `0x`-prefixed branch targets as emitted by different disassemblers. JNI correlation links Java `native` declarations to exported symbols (`confirmed`) or registration-evidence only (`candidate`), always with the supporting evidence list and limitations attached.
- Runtime traces (`trace`) ingest normalized JSONL observations and correlate them with the same static identity model: exact method signatures, ELF addresses with an explicit bias, and JNI links of `confirmed`/`supported` confidence only. An artifact-hash mismatch blocks correlation; malformed, duplicate and out-of-order records are counted, never silently accepted. Runtime evidence is additive (`runtime_trace` block, `runtime_event` evidence items) and never rewrites static findings. Absence of an event in the trace means **not observed** — it is not evidence of unreachability.
- Evidence schema: `analysis.json` carries `schema_version` (`2`), plus `run` (the analysis command with sensitive arguments redacted) and `artifact` blocks. Every finding gets a stable `finding_id` that does not depend on volatile run metadata, and `evidence_items` that separate `observation` from `interpretation`.
- Differential testing (`diff`) compares two `analysis.json` snapshots. It is a presentation-layer comparison, not a behavioral guarantee: a finding that disappears can mean remediation, packaging, or hiding — confirm out-of-band.
- Call-graph reachability is approximate; a `partial` (truncated) traversal with no hit is reported as `inconclusive`, never as a clean result. Check `detail.analysis` (`status: complete|partial`, `truncated`, `limit`) on reachability and taint findings, and the top-level `analysis` object (`status: complete|partial|not_analysed`) in `analysis.json`.
- Rule files that fail validation are listed under `rule_errors` / `rule_inventory` and never silently discarded; related coverage is then missing (`partial`).
- Blind spots (`BLIND-0001` packed, `BLIND-0002` code rules skipped, `BLIND-0003` manifest-only) mean the finding set is incomplete by construction. `blind_spots` stays a top-level `analysis.json` key as shipped (the EV-01 plan sketch had it under `analysis`; the established schema is not broken for placement). Entropy is classified by the fraction of high-entropy windows (`sustained` vs `isolated`) and by region kind (`dex` vs `native`): only a sustained high-entropy `classes*.dex` payload is a code-blinding (`BLIND-0001`) signal. A high-entropy region confined to a native library is reported as an info finding `NA-ENT-0001` (the native payload is opaque) and does **not** skip the smali code rules.

## Safety

`tests.sh` is emit-only. Nothing executes unless you pass `--execute` and type `run`. Review every line — `content query` against a misconfigured provider is data exfiltration.
