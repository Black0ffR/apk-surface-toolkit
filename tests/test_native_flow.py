"""NF-01: native-flow evidence graph tests (plan §15).

Synthetic objdump-style text and hand-built JNI records stand in for
compiled fixtures (Termux, no cross-toolchain). No native code is
executed; expectations are kept per-architecture.
"""

import unittest

from triagekit import jni as JNI
from triagekit import native_flow as NF


def _line64(addr: str, byte: str, mnem: str, rest: str) -> str:
    return "\t%s:\t%s \t%s\t%s" % (addr, byte, mnem, rest)


X86_TEXT = "\n".join([
    "0000000000001234 <my_func>:",
    _line64("1234", "e8 17 00 00 00", "callq", "1250 <target_a>"),
    _line64("1239", "ff 15 29 44 00 00", "callq", "*0x4429(%rip)"),
    _line64("123f", "c3", "retq", ""),
])

ARM64_TEXT = "\n".join([
    "0000000000001234 <my_func>:",
    _line64("1234", "94000004", "bl", "1240 <target_a>"),
    _line64("1238", "d63f0020", "blr", "x0"),
])

# llvm-objdump prints aarch64 branch targets with a 0x prefix
# (`bl 0x25c0 <sym>`), unlike GNU x86 objdump (bare hex). Both forms must
# parse; the 0x form was previously a silent false negative.
ARM64_PREFIXED_TEXT = "\n".join([
    "0000000000002244 <my_func>:",
    _line64("2244", "940000df", "bl", "0x25c0 <target_b>"),
    _line64("2248", "d63f0100", "blr", "x8"),
])

ARM64_NO_SYMBOL_TEXT = "\n".join([
    "0000000000001234 <my_func>:",
    _line64("1234", "94000004", "bl", "1240"),
])

ARM32_TEXT = "\n".join([
    "00001234 <my_func>:",
    _line64("1234", "eb000001", "bl", "1240 <target_a>"),
    _line64("1238", "e12fff30", "blx", "r0"),
])

ARM32_BLX_TEXT = "\n".join([
    "00001234 <my_func>:",
    _line64("1234", "eb000001", "blx", "1240 <target_a>"),
])


def _decl(sig="([B)[B", name="transform"):
    return JNI.parse_native_declarations(
        ".class public Lcom/example/Foo;\n"
        f".method public static native {name}{sig}\n.end method\n",
        file="Foo.smali")[0]


def _sym(name, value=0x1008, shndx=2, size=32):
    return {"name": name, "value": value, "size": size, "type": "func",
            "bind": "global", "shndx": shndx,
            "defined": shndx != 0 and value != 0}


class TestCallSiteParsing(unittest.TestCase):
    def test_x86_direct_and_indirect(self):
        sites = NF.parse_call_sites(X86_TEXT, function_id="fn", arch="x86_64")
        self.assertEqual(len(sites), 2)
        direct, indirect = sites
        self.assertEqual(direct["site"], 0x1234)
        self.assertEqual(direct["kind"], "direct")
        self.assertEqual(direct["target_address"], 0x1250)
        self.assertEqual(direct["target_symbol"], "target_a")
        self.assertEqual(indirect["kind"], "indirect")
        self.assertIsNone(indirect["target_address"])

    def test_arm64_bl_and_blr(self):
        sites = NF.parse_call_sites(ARM64_TEXT, function_id="fn",
                                    arch="aarch64")
        self.assertEqual([s["kind"] for s in sites], ["direct", "indirect"])
        self.assertEqual(sites[1]["register"], "x0")

    def test_arm64_zero_x_prefixed_target_is_direct(self):
        # Regression: llvm-objdump's `bl 0x... <sym>` must yield a direct
        # call site (previously parsed as zero direct calls).
        sites = NF.parse_call_sites(ARM64_PREFIXED_TEXT, function_id="fn",
                                    arch="aarch64")
        self.assertEqual([s["kind"] for s in sites], ["direct", "indirect"])
        self.assertEqual(sites[0]["site"], 0x2244)
        self.assertEqual(sites[0]["target_address"], 0x25c0)
        self.assertEqual(sites[0]["target_symbol"], "target_b")
        self.assertEqual(sites[1]["kind"], "indirect")

    def test_arm64_branch_without_symbol_not_direct_call(self):
        # A `bl` line lacking the `<symbol>` annotation is not a resolvable
        # direct call and must not be invented as one.
        sites = NF.parse_call_sites(ARM64_NO_SYMBOL_TEXT, function_id="fn",
                                    arch="aarch64")
        self.assertEqual(sites, [])

    def test_arm32_bl_and_blx(self):
        sites = NF.parse_call_sites(ARM32_TEXT, function_id="fn",
                                    arch="armeabi-v7a")
        self.assertEqual([s["kind"] for s in sites], ["direct", "indirect"])
        self.assertEqual(sites[1]["register"], "r0")

    def test_arm32_blx_immediate_is_direct(self):
        sites = NF.parse_call_sites(ARM32_BLX_TEXT, function_id="fn",
                                    arch="armeabi-v7a")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["kind"], "direct")
        self.assertEqual(sites[0]["target_address"], 0x1240)
        self.assertEqual(sites[0]["target_symbol"], "target_a")
        self.assertIsNone(sites[0]["register"])


class TestAbiSummary(unittest.TestCase):
    def test_x86_64_registers(self):
        abi = NF.abi_summary("x86_64")
        self.assertEqual(abi["argument_registers"][:2], ["rdi", "rsi"])
        self.assertEqual(abi["return_register"], "rax")

    def test_aarch64_registers(self):
        abi = NF.abi_summary("aarch64")
        self.assertEqual(abi["argument_registers"][:2], ["x0", "x1"])
        self.assertEqual(abi["return_register"], "x0")

    def test_arm32_registers(self):
        abi = NF.abi_summary("armeabi-v7a")
        self.assertEqual(abi["argument_registers"][:2], ["r0", "r1"])
        self.assertEqual(abi["return_register"], "r0")


class TestArchVocabulary(unittest.TestCase):
    def test_elf_machine_name_aliases_accepted(self):
        sites = NF.parse_call_sites(X86_TEXT, function_id="fn", arch="x86-64")
        self.assertEqual(len(sites), 2)
        abi = NF.abi_summary("arm")
        self.assertEqual(abi["argument_registers"][:2], ["r0", "r1"])
        self.assertEqual(abi["return_register"], "r0")
        self.assertTrue(abi["supported"])

    def test_unsupported_arch_is_explicit(self):
        abi = NF.abi_summary("mips")
        self.assertEqual(abi["argument_registers"], [])
        self.assertFalse(abi["supported"])
        records = JNI.correlate([_decl(sig="()V", name="ping")],
                                library="libx.so",
                                symbols=[_sym("Java_com_example_Foo_ping",
                                              value=0x1234)])
        graph = NF.build(library="libx.so", jni_records=records, arch="mips")
        kinds = {u["type"] for u in graph["unknowns"]}
        self.assertIn("unsupported-arch", kinds)


class TestBuildGraph(unittest.TestCase):
    def _confirmed_records(self):
        decls = [_decl(sig="()V", name="ping")]
        syms = [_sym("Java_com_example_Foo_ping", value=0x1234, size=0)]
        return JNI.correlate(decls, library="libx.so", symbols=syms)

    def test_jni_node_and_confirmed_edge(self):
        graph = NF.build(library="libx.so",
                         jni_records=self._confirmed_records())
        jni_nodes = [n for n in graph["nodes"] if n["kind"] == "jni-method"]
        fn_nodes = [n for n in graph["nodes"]
                    if n["kind"] == "native-function"]
        self.assertEqual(len(jni_nodes), 1)
        self.assertEqual(jni_nodes[0]["confidence"], "supported")
        self.assertEqual(fn_nodes[0]["id"], "elf:libx.so:0x1234")
        edges = [e for e in graph["edges"] if e["kind"] == "calls"]
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["confidence"], "confirmed")
        self.assertEqual(edges[0]["to"], "elf:libx.so:0x1234")

    def test_zero_size_symbol_does_not_claim_end(self):
        graph = NF.build(library="libx.so",
                         jni_records=self._confirmed_records())
        fn = [n for n in graph["nodes"] if n["kind"] == "native-function"][0]
        self.assertIsNone(fn["end"])
        self.assertIn("elf-dynamic-symbol", fn["boundary_evidence"])
        kinds = {u["type"] for u in graph["unknowns"]}
        self.assertIn("function-end", kinds)

    def test_candidate_jni_mapping_has_no_calls_edge(self):
        decls = [_decl()]
        records = JNI.correlate(decls, library="libx.so", symbols=[],
                                strings=["transform"])
        graph = NF.build(library="libx.so", jni_records=records)
        jni = [n for n in graph["nodes"] if n["kind"] == "jni-method"][0]
        self.assertEqual(jni["confidence"], "candidate")
        self.assertEqual([e for e in graph["edges"]
                          if e["kind"] == "calls"], [])
        kinds = {u["type"] for u in graph["unknowns"]}
        self.assertIn("unresolved-jni-mapping", kinds)

    def test_direct_call_edge_confirmed_target_candidate(self):
        graph = NF.build(
            library="libx.so",
            jni_records=self._confirmed_records(),
            disassembly={"elf:libx.so:0x1234": X86_TEXT},
            arch="x86_64")
        calls = [e for e in graph["edges"]
                 if e["kind"] == "calls" and e["to"] == "elf:libx.so:0x1250"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["confidence"], "confirmed")
        target = [n for n in graph["nodes"]
                  if n["id"] == "elf:libx.so:0x1250"]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["confidence"], "candidate")
        self.assertIn("call-site", target[0]["boundary_evidence"])

    def test_indirect_call_is_unresolved_not_confirmed(self):
        graph = NF.build(
            library="libx.so",
            jni_records=self._confirmed_records(),
            disassembly={"elf:libx.so:0x1234": X86_TEXT},
            arch="x86_64")
        unresolved = [e for e in graph["edges"]
                      if e["confidence"] == "unresolved"]
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]["kind"], "calls")
        self.assertEqual(unresolved[0]["from"], "elf:libx.so:0x1234")
        unknown_node = [n for n in graph["nodes"]
                        if n["id"] == unresolved[0]["to"]]
        self.assertEqual(unknown_node[0]["kind"], "unknown")
        kinds = {u["type"] for u in graph["unknowns"]}
        self.assertIn("indirect-call", kinds)

    def test_single_indirect_candidate_reason_is_accurate(self):
        graph = NF.build(
            library="libx.so",
            jni_records=self._confirmed_records(),
            disassembly={"elf:libx.so:0x1234": X86_TEXT},
            arch="x86_64",
            indirect_candidates={0x1239: [{"symbol": "fn_a", "va": 0x2000}]})
        types = [u["type"] for u in graph["unknowns"]]
        self.assertNotIn("multiple-indirect-targets", types)
        single = [u for u in graph["unknowns"]
                  if u["type"] == "single-indirect-target"]
        self.assertEqual(len(single), 1)
        self.assertNotIn("multiple", single[0]["reason"])

    def test_implausible_symbol_size_does_not_claim_end(self):
        syms = [_sym("Java_com_example_Foo_ping", value=0x1234,
                     size=0x7FFFFFFFFFFFFFFF)]
        records = JNI.correlate([_decl(sig="()V", name="ping")],
                                library="libx.so", symbols=syms)
        graph = NF.build(library="libx.so", jni_records=records)
        fn = [n for n in graph["nodes"]
              if n["kind"] == "native-function"][0]
        self.assertIsNone(fn["end"])
        self.assertNotIn("symbol-size", fn["boundary_evidence"])
        reason = [u["reason"] for u in graph["unknowns"]
                  if u["type"] == "function-end"][0]
        self.assertIn("size", reason)

    def test_indirect_candidates_stay_candidate(self):
        graph = NF.build(
            library="libx.so",
            jni_records=self._confirmed_records(),
            disassembly={"elf:libx.so:0x1234": X86_TEXT},
            arch="x86_64",
            indirect_candidates={0x1239: [
                {"symbol": "fn_a", "va": 0x2000},
                {"symbol": "fn_b", "va": 0x2100}]})
        to_unknown = [e for e in graph["edges"]
                      if e["confidence"] == "unresolved"]
        self.assertEqual(to_unknown, [])
        cand = [e for e in graph["edges"]
                if e["from"] == "elf:libx.so:0x1234"
                and e["confidence"] == "candidate"]
        self.assertEqual(len(cand), 2)
        targets = {e["to"] for e in cand}
        self.assertEqual(targets, {"elf:libx.so:0x2000",
                                   "elf:libx.so:0x2100"})
        kinds = {u["type"] for u in graph["unknowns"]}
        self.assertIn("multiple-indirect-targets", kinds)

    def test_aarch64_direct_call(self):
        graph = NF.build(
            library="libx.so",
            jni_records=self._confirmed_records(),
            disassembly={"elf:libx.so:0x1234": ARM64_TEXT},
            arch="aarch64")
        confirmed = [e for e in graph["edges"]
                     if e["confidence"] == "confirmed"]
        self.assertTrue(any(e["to"] == "elf:libx.so:0x1240"
                            for e in confirmed))

    def test_limitations_are_explicit(self):
        graph = NF.build(library="libx.so",
                         jni_records=self._confirmed_records())
        joined = " ".join(graph["limitations"])
        self.assertIn("not a complete data-flow analysis", joined)
        self.assertIn("boundaries", joined)

    def test_dedup_nodes_by_id(self):
        graph = NF.build(
            library="libx.so",
            jni_records=self._confirmed_records(),
            disassembly={"elf:libx.so:0x1234": X86_TEXT},
            arch="x86_64")
        ids = [n["id"] for n in graph["nodes"]]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
