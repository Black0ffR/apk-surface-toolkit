# apk-surface-toolkit

Static attack-surface mapping for Android APKs. Termux-first, stdlib-only Python. Every external binary is optional and degrades gracefully.

Two tools:

- **`bin/apk-surface`** — decode → parse manifest → run 19 JSON rules → `analysis.json` + `report.md` + emit-only `tests.sh` (`analyze|query|diff|doctor`)
- **`capdoctor`** — read-only device capability report (no network, no root prompt unless `--deep`)

## Quick start

```bash
pkg install apktool aapt2 apksigner openjdk-21
# apkid optional (packer heuristics); fails to build on Termux — skipped gracefully

./bin/apk-surface doctor
./bin/apk-surface analyze app.apk -o ./out
./bin/apk-surface query ./out/<sha12> --type activity
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
                manifest, rules, report, tests_gen (emit-only), diff, utils
rules/AS-*.json 19 rules (manifest + regex) + platform_permissions.txt
```

## Safety

`tests.sh` is emit-only. Nothing executes unless you pass `--execute` and type `run`. Review every line — `content query` against a misconfigured provider is data exfiltration.
