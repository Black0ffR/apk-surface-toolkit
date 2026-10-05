# Smali intra-method dataflow tracker — design

Date: 2026-10-05. Status: approved in chat. Next: implementation plan.

## Goal

Prove the sink, not just the entry. Current rules flag exported
components (AS-0001), custom schemes (AS-0009), and isolated sinks
(AS-0014 bridge, AS-0022 redirection heuristic) but never connect
attacker-controlled input to the dangerous call. This closes the three
highest-paying static gaps: deeplink→`loadUrl`, deeplink→auth/ATO
navigation, and `Intent`-extra→`startActivity`/`sendBroadcast`.

## Non-goals (v1)

- No inter-procedural tracking (no cross-`.method` invoke following).
- No layout-XML, assetlinks fetch, pin-digest, native disassembly, or
  arsc work (separate sub-projects).
- No dynamic execution; findings stay hypotheses with `tests.sh` probes.

## Architecture

New module `triagekit/taint_smali.py` (stdlib only, ~200 lines),
called from `analyzer.analyse()` on the same path as `check_regex`
(skipped when packed or manifest-only → counted in BLIND-0002).

```
apktool smali tree → taint_smali.scan(decoded, rules) → findings
```

Rule kind `smali-taint`: `AS-0033` (deeplink→WebView, high),
`AS-0034` (intent redirection, high). Params: `sources`, `sinks`,
`cap` (default 15).

## Components

1. **Method splitter** — split each `.smali` file into `.method … .end
   method` blocks (ignore vendor prefixes + `res`/`assets`, same lists
   as `check_regex`).
2. **Source tagger** — lines matching source patterns
   (`getIntent|getData|getStringExtra|getParcelableExtra|
   getSerializableExtra`) taint the `move-result* vN` register on the
   next line. `move*` aliases propagate taint within the block.
3. **Sink checker** — `invoke*` lines matching sink patterns
   (`loadUrl|addJavascriptInterface|startActivity|startService|
   sendBroadcast|setClass`) whose `{...}` arg list contains a tainted
   register emit one finding: file, method signature, source line,
   sink line, register path.
4. **Cap + honesty** — per-rule cap 15; over-cap marks
   `detail.truncated=true` and appends `[truncated at N hits]`,
   mirroring `check_regex`.

## Data flow

`analyse()` loads `smali-taint` rules via existing `R.load_dir`,
calls `taint_smali.scan()` after `check_regex`, extends the
`analysis.json` findings list. `report.py` needs no change (generic
finding renderer). `tests_gen.py` gains per-finding deeplink/intent
probes reusing existing emitters.

## Error handling

- Malformed smali (truncated method, no `.end method`): scan to EOF,
  never raise; rule continues to next file.
- `OSError` on read: skip file (matches `check_regex`).
- Packed / manifest-only: skipped, counted in BLIND-0002 (no silent
  clean).
- Vendor dirs: skipped by default; `include_vendor=true` opts back in.

## Testing

- Unit fixture: 3 synthetic `.smali` methods — direct
  `getIntent→loadUrl` flow (must fire), clean method using constants
  (must not fire), cross-method flow (must not fire in v1, documents
  the boundary).
- Regression: full `bin/apk-surface analyze` on InsecureBankv2 must
  finish inside the established 280s on-phone budget with no new vendor
  findings.
- TDD: fixture first, watch it fail, then implement.

## Rollout

Land behind existing exit codes (findings only change counts).
Commit message references this spec. Follow-up sub-projects
(layout analyzer, network validators, native+arsc) each get their
own spec cycle.
