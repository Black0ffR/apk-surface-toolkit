"""RL-01/TEST-01 test-to-rule map for the shipped rule corpus.

Single source of truth connecting every shipped rule (rules/AS-*.json) to:
  * the analyzer path it is exercised through (rule.kind -> execution point),
  * a positive fixture directory per scenario + finding matchers that must be
    satisfied by real findings emitted by that path,
  * a negative fixture directory where the rule must emit zero findings.

Auditability contract (enforced by tests/test_rule_coverage.py):
  * set(RULE_CASES) | set(UNTESTED) == set(shipped rule ids), disjoint;
  * every case's "path" equals the shipped rule's kind;
  * every referenced fixture directory exists and is non-empty;
  * a shipped rule with no entry fails the partition test, forcing the author
    of a new rule to add fixtures or an UNTESTED entry with a reason.

Matcher fields (all optional, all must hold; at least one required):
  severity, component, file_contains, evidence_contains, detail (recursive
  subset of the finding's detail dict).

Fixture layout: tests/fixtures/decoded/<RID>/{positive*,negative}/
  * manifest-kind rules: AndroidManifest.xml (+ res/xml/* where the rule needs
    nsc / file paths / backup rules);
  * regex-kind rules: any files matching the rule's exts/root;
  * smali-taint rules: smali/**/*.smali;
  * reachability rules: AndroidManifest.xml + smali/**/*.smali;
  * AS-0028 additionally carries sig.json (signature verdict input).
"""
from __future__ import annotations

RULE_CASES: dict[str, dict] = {
    # ------------------------------------------------------------- manifest
    "AS-0001": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0001/positive",
            "expect": [{
                "severity": "medium",
                "component": "com.example.app.ExportedActivity",
                "evidence_contains": "exported with no permission",
            }],
        }],
        "negative": {"dir": "AS-0001/negative"},
        "notes": "negative = exported with a permission (near miss, not merely "
                 "non-exported); launcher-activity exclusion is covered by "
                 "tests/test_analyzer_manifest.py where present",
    },
    "AS-0002": {
        "path": "manifest",
        "positive": [{
            "name": "severity_classification",
            "dir": "AS-0002/positive",
            "expect": [
                {
                    "severity": "high",
                    "component": "com.example.app.OwnNamespace",
                    "evidence_contains": "never declared",
                },
                {
                    "severity": "medium",
                    "component": "com.example.app.AndroidUnknown",
                    "evidence_contains": "not a known platform permission",
                },
                {
                    "severity": "low",
                    "component": "com.example.app.ThirdParty",
                    "evidence_contains": "third-party permission string",
                },
            ],
        }],
        "negative": {"dir": "AS-0002/negative"},
        "notes": "positive exercises all three severity overrides; negative = "
                 "declared own permission + a real android.permission.* name, "
                 "and a uses-permission INTERNET that must never be treated as "
                 "a component guard (platform_permissions.txt is a "
                 "component-guard snapshot, so INTERNET's absence is intended)",
    },
    "AS-0003": {
        "path": "manifest",
        "positive": [{
            "name": "plain_and_file_provider",
            "dir": "AS-0003/positive",
            "expect": [
                {
                    "severity": "high",
                    "component": "com.example.app.LeakyProvider",
                    "evidence_contains": "exported provider with no read permission",
                },
                {
                    "severity": "info",
                    "component": "com.example.app.MyFileProvider",
                    "evidence_contains": "FileProvider-style provider",
                    "detail": {"class": "file_provider"},
                },
            ],
        }],
        "negative": {"dir": "AS-0003/negative"},
        "notes": "file_provider_severity override (high -> info) asserted via "
                 "the second matcher; negative = exported provider WITH a read "
                 "permission",
    },
    "AS-0004": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0004/positive",
            "expect": [{
                "severity": "info",
                "evidence_contains": 'android:allowBackup="true"',
                "detail": {"flag": "allowBackup"},
            }],
        }],
        "negative": {"dir": "AS-0004/negative"},
        "notes": "negative = allowBackup explicitly false",
    },
    "AS-0005": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0005/positive",
            "expect": [{
                "severity": "info",
                "evidence_contains": 'android:debuggable="true"',
                "detail": {"flag": "debuggable"},
            }],
        }],
        "negative": {"dir": "AS-0005/negative"},
        "notes": "negative = debuggable explicitly false",
    },
    "AS-0006": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0006/positive",
            "expect": [{
                "severity": "medium",
                "evidence_contains": 'android:usesCleartextTraffic="true"',
                "detail": {"flag": "usesCleartextTraffic"},
            }],
        }],
        "negative": {"dir": "AS-0006/negative"},
        "notes": "negative = usesCleartextTraffic false",
    },
    "AS-0007": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0007/positive",
            "expect": [{
                "severity": "medium",
                "file_contains": "network_security_config.xml",
                "evidence_contains": "debug-overrides",
            }],
        }],
        "negative": {"dir": "AS-0007/negative"},
        "notes": "contract comes from res/xml/network_security_config.xml, not "
                 "the manifest; negative config has no <debug-overrides>",
    },
    "AS-0008": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0008/positive",
            "expect": [{
                "severity": "medium",
                "evidence_contains": 'cleartextTrafficPermitted="true"',
            }],
        }],
        "negative": {"dir": "AS-0008/negative"},
        "notes": "negative = domain-config without cleartextTrafficPermitted",
    },
    "AS-0009": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0009/positive",
            "expect": [{
                "severity": "low",
                "component": "com.example.app.SchemeActivity",
                "evidence_contains": 'scheme="mycustomapp"',
                "detail": {"scheme": "mycustomapp"},
            }],
        }],
        "negative": {"dir": "AS-0009/negative"},
        "notes": "negative = same custom scheme on a NON-exported activity "
                 "(not external attack surface)",
    },
    "AS-0010": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0010/positive",
            "expect": [{
                "severity": "info",
                "component": "com.example.app.LinkActivity",
                "evidence_contains": "without android:autoVerify",
            }],
        }],
        "negative": {"dir": "AS-0010/negative"},
        "notes": "negative = same https link WITH autoVerify=\"true\"",
    },
    "AS-0011": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0011/positive",
            "expect": [{
                "severity": "info",
                "evidence_contains": "android.permission.CAMERA",
                "detail": {"count": 1},
            }],
        }],
        "negative": {"dir": "AS-0011/negative"},
        "notes": "aggregated rule: positive has exactly one dangerous "
                 "permission; negative has INTERNET only",
    },
    "AS-0012": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0012/positive",
            "expect": [{
                "severity": "low",
                "evidence_contains": "protectionLevel=",
                "detail": {"name": "com.example.app.permission.ACT"},
            }],
        }],
        "negative": {"dir": "AS-0012/negative"},
        "notes": "negative = protectionLevel=\"signature\"",
    },
    "AS-0018": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0018/positive",
            "expect": [{
                "severity": "low",
                "evidence_contains": 'android:requestLegacyExternalStorage="true"',
            }],
        }],
        "negative": {"dir": "AS-0018/negative"},
        "notes": "negative = requestLegacyExternalStorage false",
    },
    "AS-0024": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0024/positive",
            "expect": [{
                "severity": "high",
                "file_contains": "file_paths.xml",
                "evidence_contains": "grants broad access",
            }],
        }],
        "negative": {"dir": "AS-0024/negative"},
        "notes": "contract comes from res/xml/file_paths.xml; positive has "
                 "root-path, negative a scoped files-path",
    },
    "AS-0025": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0025/positive",
            "expect": [{
                "severity": "medium",
                "evidence_contains": 'meta-data API_KEY=',
            }],
        }],
        "negative": {"dir": "AS-0025/negative"},
        "notes": "negative = meta-data with a non-secret name",
    },
    "AS-0026": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0026/positive",
            "expect": [{
                "severity": "medium",
                "component": "com.example.app.HijackableActivity",
                "evidence_contains": 'taskAffinity="com.other.app"',
            }],
        }],
        "negative": {"dir": "AS-0026/negative"},
        "notes": "negative = foreign affinity but no singleTask/reparent "
                 "(condition requires both halves)",
    },
    "AS-0027": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0027/positive",
            "expect": [{
                "severity": "info",
                "evidence_contains": "exported activit",
                "detail": {"count": 1},
            }],
        }],
        "negative": {"dir": "AS-0027/negative"},
        "notes": "negative = only non-exported activities",
    },
    "AS-0028": {
        "path": "manifest",
        "positive": [
            {
                "name": "debug_cert",
                "dir": "AS-0028/positive_debug",
                "expect": [{
                    "severity": "medium",
                    "evidence_contains": "signed with debug certificate",
                }],
            },
            {
                "name": "v1_only_janus",
                "dir": "AS-0028/positive_v1only",
                "expect": [{
                    "severity": "medium",
                    "evidence_contains": "v1-only signature with minSdk 26",
                }],
            },
        ],
        "negative": {"dir": "AS-0028/negative"},
        "notes": "signature verdict normally comes from apktools.signature "
                 "(needs a real APK); fixtures supply sig.json — documented "
                 "limitation; negative = v1+v2 with a release DN",
    },
    "AS-0029": {
        "path": "manifest",
        "positive": [{
            "name": "canonical_base_user_ca",
            "dir": "AS-0029/positive",
            "expect": [{
                "severity": "medium",
                "evidence_contains": "user trust anchors in base-config",
            }],
        }, {
            "name": "canonical_domain_config_user_ca",
            "dir": "AS-0029/domain_config",
            "expect": [{
                "severity": "medium",
                "evidence_contains": "user trust anchors in domain-config",
            }],
        }, {
            "name": "uninterpreted_trust_anchors",
            "dir": "AS-0029/uninterpreted",
            "expect": [{
                "severity": "medium",
                "evidence_contains": "user trust cannot be excluded",
            }],
        }],
        "negative": {"dir": "AS-0029/negative"},
        "notes": "positive fixtures use the canonical "
                 "<trust-anchors><certificates src=\"user\"/> schema "
                 "(base-config, domain-config, uninterpreted child); "
                 "negative = canonical system anchors only",
    },
    "AS-0030": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0030/positive",
            "expect": [{
                "severity": "info",
                "evidence_contains": "no <pin-set>",
            }],
        }],
        "negative": {"dir": "AS-0030/negative"},
        "notes": "negative = domain-config with a <pin-set>",
    },
    "AS-0031": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0031/positive",
            "expect": [{
                "severity": "low",
                "file_contains": "backup_rules.xml",
                "evidence_contains": "backs up broadly",
            }],
        }],
        "negative": {"dir": "AS-0031/negative"},
        "notes": "contract comes from res/xml/backup_rules.xml referenced by "
                 "dataExtractionRules; negative includes a scoped path only",
    },
    "AS-0032": {
        "path": "manifest",
        "positive": [{
            "name": "testOnly",
            "dir": "AS-0032/positive",
            "expect": [{
                "severity": "info",
                "evidence_contains": 'android:testOnly="true"',
                "detail": {"flag": "testOnly"},
            }],
        }],
        "negative": {"dir": "AS-0032/negative"},
        "notes": "multi-flag rule; testOnly is the scoped case (other flags "
                 "share the same code path)",
    },
    "AS-0035": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0035/positive",
            "expect": [{
                "severity": "medium",
                "component": "com.example.app.GuardedActivity",
                "evidence_contains": "protectionLevel=\"normal\"",
            }],
        }],
        "negative": {"dir": "AS-0035/negative"},
        "notes": "negative = same permission declared at signature level",
    },
    "AS-0036": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0036/positive",
            "expect": [{
                "severity": "low",
                "component": "com.example.app.AutoVerifyActivity",
                "evidence_contains": 'exported BROWSABLE scheme "mycustomapp"',
                "detail": {"scheme": "mycustomapp"},
            }],
        }],
        "negative": {"dir": "AS-0036/negative"},
        "notes": "negative = autoVerify on https (web scheme: verification "
                 "actually runs, rule must stay silent)",
    },
    "AS-0037": {
        "path": "manifest",
        "positive": [{
            "name": "default",
            "dir": "AS-0037/positive",
            "expect": [{
                "severity": "low",
                "evidence_contains": "no android:networkSecurityConfig",
            }],
        }],
        "negative": {"dir": "AS-0037/negative"},
        "notes": "negative = networkSecurityConfig attribute present",
    },
    # ---------------------------------------------------------------- regex
    "AS-0013": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0013/positive",
            "expect": [{
                "severity": "high",
                "file_contains": "Net.java",
                "evidence_contains": "checkServerTrusted",
            }],
        }],
        "negative": {"dir": "AS-0013/negative"},
        "notes": "negative exercises the near-miss sibling call "
                 "checkClientTrusted( only",
    },
    "AS-0014": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0014/positive",
            "expect": [{
                "severity": "high",
                "file_contains": "Bridge.java",
                "evidence_contains": "addJavascriptInterface",
            }],
        }],
        "negative": {"dir": "AS-0014/negative"},
        "notes": "pattern is a substring match; negative file contains no "
                 "occurrence at all",
    },
    "AS-0015": {
        "path": "regex",
        "positive": [{
            "name": "message_digest_md5",
            "dir": "AS-0015/positive",
            "expect": [{
                "severity": "medium",
                "file_contains": "Crypto.java",
                "evidence_contains": "MessageDigest",
            }],
        }, {
            "name": "cipher_bare_aes",
            "dir": "AS-0015/cipher_bare_aes",
            "expect": [{
                "severity": "medium",
                "file_contains": "Crypto.java",
                "evidence_contains": 'getInstance("AES")',
            }],
        }, {
            "name": "cipher_ecb_mode",
            "dir": "AS-0015/cipher_ecb_mode",
            "expect": [{
                "severity": "medium",
                "file_contains": "Crypto.java",
                "evidence_contains": "AES/ECB/PKCS5Padding",
            }],
        }],
        "negative": {"dir": "AS-0015/negative"},
        "notes": "covers the MessageDigest branch and both Cipher branches "
                 "(bare AES defaults to ECB; explicit /ECB/...); negative "
                 "blocks GCM, CBC, SHA-256 and RSA/ECB with no false hits",
    },
    "AS-0016": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0016/positive",
            "expect": [{
                "severity": "high",
                "file_contains": "config.json",
                "evidence_contains": "AIza",
            }],
        }],
        "negative": {"dir": "AS-0016/negative"},
        "notes": "positive is an AIza-shaped key (pattern branch, not the "
                 "entropy fallback); negative file has no credential shape",
    },
    "AS-0017": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0017/positive",
            "expect": [{
                "severity": "low",
                "file_contains": "Loader.java",
                "evidence_contains": "DexClassLoader",
            }],
        }],
        "negative": {"dir": "AS-0017/negative"},
        "notes": "negative avoids loadClass/DexClassLoader/PathClassLoader",
    },
    "AS-0019": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0019/positive",
            "expect": [{
                "severity": "critical",
                "file_contains": "InsecureTrust.java",
                "evidence_contains": "TrustManager",
            }],
        }],
        "negative": {"dir": "AS-0019/negative"},
        "notes": "negative avoids every branch: no TrustManager class name, "
                 "no checkServerTrusted, no X509TrustManager",
    },
    "AS-0020": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0020/positive",
            "expect": [{
                "severity": "medium",
                "file_contains": "config.xml",
                "evidence_contains": "firebaseio.com",
            }],
        }],
        "negative": {"dir": "AS-0020/negative"},
        "notes": "negative has a plain endpoint but no firebase/googleapis "
                 "token",
    },
    "AS-0021": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0021/positive",
            "expect": [{
                "severity": "info",
                "file_contains": "endpoints.json",
                "evidence_contains": "https://",
            }],
        }],
        "negative": {"dir": "AS-0021/negative"},
        "notes": "negative has no URL-shaped string at all",
    },
    "AS-0022": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0022/positive",
            "expect": [{
                "severity": "medium",
                "file_contains": "Redirect.java",
                "evidence_contains": "getIntent().get",
            }],
        }],
        "negative": {"dir": "AS-0022/negative"},
        "notes": "negative reads the intent without an Extra accessor and "
                 "never starts/broadcasts from it",
    },
    "AS-0023": {
        "path": "regex",
        "positive": [{
            "name": "default",
            "dir": "AS-0023/positive",
            "expect": [{
                "severity": "medium",
                "file_contains": "Web.java",
                "evidence_contains": "setJavaScriptEnabled(true)",
            }],
        }],
        "negative": {"dir": "AS-0023/negative"},
        "notes": "negative = setJavaScriptEnabled(false) and no .loadUrl( "
                 "branch",
    },
    # ----------------------------------------------------------- smali-taint
    "AS-0033": {
        "path": "smali-taint",
        "positive": [{
            "name": "default",
            "dir": "AS-0033/positive",
            "expect": [{
                "severity": "high",
                "file_contains": "MainActivity.smali",
                "evidence_contains": "reaches loadUrl",
                "detail": {"sink": "loadUrl",
                           "analysis": {"status": "partial"}},
            }],
        }],
        "negative": {"dir": "AS-0033/negative"},
        "notes": "negative = loadUrl with a const-string URL (sink without "
                 "source); gap-in-method variants covered by cross-component "
                 "fixtures under tests/fixtures/cross/",
    },
    "AS-0034": {
        "path": "smali-taint",
        "positive": [{
            "name": "default",
            "dir": "AS-0034/positive",
            "expect": [{
                "severity": "high",
                "file_contains": "RedirectActivity.smali",
                "evidence_contains": "reaches setClass",
                "detail": {"sink": "setClass",
                           "analysis": {"status": "partial"}},
            }],
        }],
        "negative": {"dir": "AS-0034/negative"},
        "notes": "negative = startActivity with an untainted intent",
    },
    # ---------------------------------------------------------- reachability
    "AS-0038": {
        "path": "reachability",
        "positive": [{
            "name": "default",
            "dir": "AS-0038/positive",
            "expect": [{
                "severity": "high",
                "component": "com.example.app.Entry",
                "evidence_contains": "reaches loadUrl",
                "detail": {"sink": "loadUrl",
                           "analysis": {"status": "complete"}},
            }],
        }],
        "negative": {"dir": "AS-0038/negative"},
        "notes": "negative = exported entry with smali that reaches no sink",
    },
}

# Rules that cannot be exercised: {rule id: reason}. Must stay in sync with
# RULE_CASES by the partition test, and every reason must be non-empty.
UNTESTED: dict[str, str] = {}
