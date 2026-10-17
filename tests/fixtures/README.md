# Rule coverage fixtures (Batch F — RL-01 + TEST-01)

Synthetic decoded-APK trees used by `tests/test_rule_coverage.py` to exercise
every shipped rule through its real analyzer path. The auditable test-to-rule
mapping is `tests/rule_fixture_map.py` (`RULE_CASES`, 38 entries;
`UNTESTED` must stay empty and is enforced by `TestRegistryAudit`).

## Layout

```
fixtures/
  decoded/<RULE-ID>/positive/   minimal decoded tree that must trigger the rule
  decoded/<RULE-ID>/negative/   nearest look-alike that must NOT trigger it
  cross/                        shared trees for cross-component tests
```

Each positive/negative dir contains only what the rule needs:

- manifest-path rules: `AndroidManifest.xml` (+ `res/xml/...` network security
  config or backup rules, `data/...`, `res/...` for file-provider paths)
- regex rules: any text file the scanner walks (`.java`, `.json`, ...)
- smali-taint rules (AS-0033/0034): `smali/com/example/app/*.smali`
- reachability rules (AS-0038): manifest entry point + `smali/` implementation

## How tests run a fixture

`tests/test_rule_coverage.py::run_rule` dispatches on `rule.kind`, passing only
the rule under test so findings are attributable:

- manifest → `analyzer.check_manifest([rule], mf.parse(dir), nsc, PLATFORM,
  file_paths, sig, backup_rules)`
- regex → `analyzer.check_regex([rule], dir)`
- smali-taint → `taint_smali.scan(dir, [rule])`
- reachability → `callgraph.check_reachability([rule], dir, man)`

Signature rules (AS-0028) read a `sig.json` fixture instead of
`apktools.signature` (which requires an APK); the file mimics that verdict
dict.

## Known limitations of the fixtures

- AS-0015 positives exercise all three branches: `MessageDigest` MD5, bare
  `Cipher.getInstance("AES")` (defaults to ECB), and explicit
  `"AES/ECB/PKCS5Padding"`. The Batch F pattern quirk that made the whole
  `Cipher.getInstance` branch dead is fixed; the negative fixture pins
  GCM/CBC/SHA-256/RSA-ECB as clean. Resolved in Batch J.
- AS-0029 positives use the canonical Android schema
  (`<trust-anchors><certificates src="user"/></trust-anchors>`) across
  base-config, domain-config, and an uninterpreted-child variant; the legacy
  `<anchors src="..."/>` dialect is still parsed (unit-covered in
  `tests/test_nsc_parsing.py`). Resolved in Batch J.
- `rules/platform_permissions.txt` deliberately does not list `INTERNET`:
  the file is a snapshot of permissions that can guard *components*
  (`android:permission=`), and `INTERNET` is only ever a `uses-permission`.
  AS-0002's negative fixture includes `uses-permission INTERNET` to pin that
  no `uses-permission` is ever classified as a custom/forged guard.
  Ruling recorded in Batch J; no change to the list.
