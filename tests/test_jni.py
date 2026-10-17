"""JNI-01: Java/native correlation tests (plan §13).

All fixtures are synthetic: smali text built in-memory, symbol tables built
from plain dicts (shaped like triagekit.elf.parse_dynamic_symbols output),
plus one integration case reusing the ELF section-table fixture builder.
No native code is executed and no external ELF tool is invoked.
"""

import unittest

from triagekit import elf as ELF
from triagekit import jni as JNI
from tests.test_elf import _build_symtab


def _sym(name, value=0x1008, shndx=2, bind="global"):
    return {
        "name": name,
        "value": value,
        "size": 32,
        "type": "func",
        "bind": bind,
        "shndx": shndx,
        "defined": shndx != 0 and value != 0,
    }


SMALI_FOO = """
.class public Lcom/example/Foo;
.super Ljava/lang/Object;

# direct methods
.method public constructor <init>()V
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static native transform([B)[B
.end method

.method private native idle()V
.end method
"""


class TestParseNativeDeclarations(unittest.TestCase):
    def test_basic_declaration(self):
        decls = JNI.parse_native_declarations(SMALI_FOO, file="Foo.smali")
        self.assertEqual(len(decls), 2)
        d = decls[0]
        self.assertEqual(d["java_method"], "Lcom/example/Foo;->transform([B)[B")
        self.assertEqual(d["class_descriptor"], "Lcom/example/Foo;")
        self.assertEqual(d["method_name"], "transform")
        self.assertEqual(d["signature"], "([B)[B")
        self.assertIn("static", d["flags"])
        self.assertNotIn("native", d["flags"])
        self.assertEqual(d["file"], "Foo.smali")
        self.assertGreater(d["line"], 0)

    def test_ignores_non_native_methods(self):
        smali = """
.class public Lcom/example/Foo;
.method public call()V
    return-void
.end method
"""
        self.assertEqual(JNI.parse_native_declarations(smali), [])

    def test_explicit_class_descriptor_overrides(self):
        smali = ".method public native ping()V\n.end method\n"
        decls = JNI.parse_native_declarations(
            smali, class_descriptor="Lcom/other/Bar;")
        self.assertEqual(decls[0]["java_method"],
                         "Lcom/other/Bar;->ping()V")


class TestMangling(unittest.TestCase):
    def test_conventional_candidates(self):
        cands = JNI.jni_symbol_candidates(
            "Lcom/example/Foo;", "transform", "([B)[B")
        self.assertEqual(cands[0], "Java_com_example_Foo_transform")
        self.assertIn("Java_com_example_Foo_transform___3B", cands)
        self.assertIn("Java_com_example_Foo_transform___3B_3B", cands)

    def test_no_signature_single_candidate(self):
        cands = JNI.jni_symbol_candidates("Lcom/example/Foo;", "ping")
        self.assertEqual(cands, ["Java_com_example_Foo_ping"])

    def test_escapes_underscore_dollar_and_brackets(self):
        cands = JNI.jni_symbol_candidates(
            "Lcom/example/Foo$Bar;", "native_process_data", "()V")
        self.assertEqual(
            cands[0], "Java_com_example_Foo_00024Bar_native_1process_1data")
        self.assertIn("Java_com_example_Foo_00024Bar_native_1process_1data__",
                      cands)
        self.assertIn("Java_com_example_Foo_00024Bar_native_1process_1data__V",
                      cands)

    def test_unicode_escape(self):
        cands = JNI.jni_symbol_candidates("Lcom/example/Foo;", "café", "()V")
        self.assertEqual(cands[0], "Java_com_example_Foo_caf_000e9")

    def test_object_argument_escape(self):
        cands = JNI.jni_symbol_candidates(
            "Lcom/example/Foo;", "format",
            "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;")
        self.assertIn(
            "Java_com_example_Foo_format__Ljava_lang_String_2_3Ljava_lang_Object_2",
            cands)


class TestCorrelation(unittest.TestCase):
    def _decl(self, sig="([B)[B", name="transform"):
        return JNI.parse_native_declarations(
            ".class public Lcom/example/Foo;\n"
            f".method public static native {name}{sig}\n.end method\n",
            file="Foo.smali")[0]

    def test_confirmed_symbol_match(self):
        decls = [self._decl()]
        syms = [_sym("Java_com_example_Foo_transform___3B", value=0x2000)]
        recs = JNI.correlate(decls, library="libexample.so", symbols=syms)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["mapping_type"], "conventional-symbol")
        self.assertEqual(rec["confidence"], "confirmed_symbol_match")
        self.assertEqual(rec["native_symbol"],
                         "Java_com_example_Foo_transform___3B")
        self.assertEqual(rec["elf_virtual_address"], 0x2000)
        self.assertEqual(rec["native_library"], "libexample.so")
        types = {e["type"] for e in rec["evidence"]}
        self.assertIn("smali-native-declaration", types)
        self.assertIn("elf-dynamic-symbol", types)

    def test_short_name_preferred_match(self):
        decls = [self._decl(sig="()V", name="ping")]
        syms = [_sym("Java_com_example_Foo_ping", value=0x1000)]
        rec = JNI.correlate(decls, library="libexample.so", symbols=syms)[0]
        self.assertEqual(rec["native_symbol"], "Java_com_example_Foo_ping")
        self.assertEqual(rec["confidence"], "confirmed_symbol_match")

    def test_overload_matches_only_its_signature(self):
        a = self._decl(sig="([B)[B", name="run")
        b = self._decl(sig="(I)V", name="run")
        syms = [_sym("Java_com_example_Foo_run___3B", value=0x3000)]
        recs = JNI.correlate([a, b], library="libexample.so", symbols=syms)
        self.assertEqual(recs[0]["confidence"], "confirmed_symbol_match")
        self.assertEqual(recs[0]["native_symbol"],
                         "Java_com_example_Foo_run___3B")
        self.assertNotEqual(recs[1]["confidence"], "confirmed_symbol_match")
        self.assertIsNone(recs[1]["native_symbol"])

    def test_decoy_string_not_confirmed(self):
        decls = [self._decl()]
        rec = JNI.correlate(
            decls, library="libexample.so", symbols=[],
            strings=["transform", "hello"])[0]
        self.assertEqual(rec["confidence"],
                         "candidate_string_or_table_match")
        self.assertIsNone(rec["native_symbol"])
        joined = " ".join(rec["limitations"])
        self.assertIn("string", joined)

    def test_register_natives_string_is_candidate_only(self):
        decls = [self._decl()]
        rec = JNI.correlate(
            decls, library="libexample.so", symbols=[],
            strings=["RegisterNatives"])[0]
        self.assertEqual(rec["confidence"],
                         "candidate_string_or_table_match")
        self.assertNotEqual(rec["confidence"], "supported_registration_match")

    def test_supported_table_evidence_requires_defined_function(self):
        decls = [self._decl()]
        syms = [_sym("JNI_OnLoad", value=0x900),
                _sym("native_transform", value=0x1234)]
        table = [{"name": "transform", "signature": "([B)[B",
                  "function": "native_transform", "file_offset": 0x40}]
        rec = JNI.correlate(
            decls, library="libexample.so", symbols=syms,
            strings=["RegisterNatives", "transform"], table_evidence=table)[0]
        self.assertEqual(rec["mapping_type"], "dynamic-registration-candidate")
        self.assertEqual(rec["confidence"], "supported_registration_match")
        self.assertEqual(rec["native_symbol"], "native_transform")
        self.assertEqual(rec["elf_virtual_address"], 0x1234)

    def test_unvalidated_table_pointer_downgrades(self):
        decls = [self._decl()]
        table = [{"name": "transform", "signature": "([B)[B",
                  "function": "who_knows", "file_offset": 0x40}]
        rec = JNI.correlate(
            decls, library="libexample.so", symbols=[],
            strings=["transform"], table_evidence=table)[0]
        self.assertEqual(rec["confidence"],
                         "candidate_string_or_table_match")
        self.assertIsNone(rec["native_symbol"])
        joined = " ".join(rec["limitations"])
        self.assertIn("not", joined)

    def test_unresolved_without_evidence(self):
        decls = [self._decl()]
        rec = JNI.correlate(decls, library="libexample.so", symbols=[],
                            strings=[])[0]
        self.assertEqual(rec["mapping_type"], "unresolved")
        self.assertEqual(rec["confidence"], "unresolved")

    def test_multiple_abis_reported_per_library(self):
        decls = [self._decl(sig="()V", name="ping")]
        arm64 = [_sym("Java_com_example_Foo_ping", value=0x5000)]
        arm32 = []
        recs = [
            JNI.correlate(decls, library="arm64-v8a/libexample.so",
                          symbols=arm64)[0],
            JNI.correlate(decls, library="armeabi-v7a/libexample.so",
                          symbols=arm32)[0],
        ]
        self.assertEqual(recs[0]["confidence"], "confirmed_symbol_match")
        self.assertEqual(recs[1]["confidence"], "unresolved")
        self.assertEqual(recs[1]["native_library"],
                         "armeabi-v7a/libexample.so")


class TestElfIntegration(unittest.TestCase):
    def test_symbols_from_elf_fixture(self):
        name = "Java_com_example_Foo_transform___3B"
        data = _build_symtab([{"name": name, "value": 0x1008,
                               "size": 32, "info": 0x12, "shndx": 2}])
        syms, errors = ELF.parse_dynamic_symbols(data)
        self.assertEqual(errors, [])
        decls = JNI.parse_native_declarations(
            ".class public Lcom/example/Foo;\n"
            ".method public static native transform([B)[B\n.end method\n")
        rec = JNI.correlate(decls, library="libexample.so", symbols=syms)[0]
        self.assertEqual(rec["confidence"], "confirmed_symbol_match")
        self.assertEqual(rec["native_symbol"], name)
        self.assertEqual(rec["elf_virtual_address"], 0x1008)


class TestMalformedSignatures(unittest.TestCase):
    """F7: untrusted smali descriptors must never make the parser raise."""

    def test_unterminated_object_descriptor_does_not_raise(self):
        got = JNI.jni_symbol_candidates("Lcom/example/Foo;", "foo", "(Lbar)V")
        self.assertIn("Java_com_example_Foo_foo", got)
        self.assertTrue(any("__" in c for c in got))

    def test_unterminated_array_descriptor_does_not_raise(self):
        got = JNI.jni_symbol_candidates("Lcom/example/Foo;", "foo", "([Lbar)V")
        self.assertIn("Java_com_example_Foo_foo", got)

    def test_well_formed_signature_yields_overload_names(self):
        got = JNI.jni_symbol_candidates("Lcom/example/Foo;", "foo",
                                        "(Ljava/lang/String;)V")
        self.assertIn("Java_com_example_Foo_foo__Ljava_lang_String_2", got)


class TestSymbolTableErrors(unittest.TestCase):
    """F12: unresolved-from-empty vs unresolved-from-broken tables differ."""

    def test_unresolved_marks_unparseable_symbol_table(self):
        decls = JNI.parse_native_declarations(SMALI_FOO, file="Foo.smali")
        recs = JNI.correlate(decls, library="libfoo.so", symbols=[],
                             symbol_errors=["bad dynstr offset"])
        self.assertEqual(recs[0]["mapping_type"], "unresolved")
        joined = " ".join(recs[0]["limitations"]).lower()
        self.assertIn("parse error", joined)
        self.assertIn("unparseable", joined)

    def test_clean_empty_table_keeps_original_reason(self):
        decls = JNI.parse_native_declarations(SMALI_FOO, file="Foo.smali")
        recs = JNI.correlate(decls, library="libfoo.so", symbols=[])
        self.assertIn("no matching exported symbol or registration evidence",
                      recs[0]["limitations"])


class TestSignaturelessTableEntry(unittest.TestCase):
    def _decl(self, sig):
        return JNI.parse_native_declarations(
            ".class public Lcom/example/Foo;\n"
            f".method public static native foo{sig}\n.end method\n",
            file="Foo.smali")[0]

    def test_signatureless_entry_cannot_support_multiple_overloads(self):
        decls = [self._decl("(I)V"), self._decl("(J)V")]
        syms = [_sym("nf", value=0x1234)]
        table = [{"name": "foo", "function": "nf", "file_offset": 0x40}]
        recs = JNI.correlate(decls, library="libexample.so", symbols=syms,
                             table_evidence=table)
        self.assertEqual(len(recs), 2)
        for rec in recs:
            self.assertNotEqual(rec["confidence"],
                                "supported_registration_match")
            self.assertEqual(rec["confidence"],
                             "candidate_string_or_table_match")
            joined = " ".join(rec["limitations"])
            self.assertIn("signature", joined)


class TestCapabilities(unittest.TestCase):
    def test_capabilities_is_dict_and_never_crashes(self):
        caps = JNI.capabilities()
        self.assertIsInstance(caps, dict)
        for key in ("readelf", "llvm-readelf"):
            self.assertIn(key, caps)
            self.assertIsInstance(caps[key], bool)


if __name__ == "__main__":
    unittest.main()
