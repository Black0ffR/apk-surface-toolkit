"""Batch E parser tests (TF-03 / §7.4). Synthetic lines only; no APK execution.

The parser is deliberately conservative: only the documented grammar is
"parsed"; anything instruction-shaped outside the grammar is "unsupported";
operand failures and non-instruction garbage are "malformed"; valid lines
with no taint-relevant value effect are "irrelevant".
"""
from __future__ import annotations

import unittest

from triagekit import smali_parse as SP


class TestSupportedGrammar(unittest.TestCase):
    def test_invoke_virtual_full_parse(self):
        item = SP.parse_line(
            "    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"
        )
        self.assertEqual(item["status"], "parsed")
        self.assertEqual(item["opcode"], "invoke-virtual")
        self.assertEqual(item["registers"], ["p0", "v0"])
        self.assertEqual(item["ref"], {
            "owner": "Landroid/webkit/WebView;",
            "name": "loadUrl",
            "descriptor": "(Ljava/lang/String;)V",
        })
        self.assertFalse(item["invoke_static"])
        self.assertEqual(item["reason"], "")

    def test_invoke_static_range_expands_and_marks_static(self):
        item = SP.parse_line(
            "    invoke-static/range {v0 .. v2}, Lx/Util;->join("
            "[Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"
        )
        self.assertEqual(item["status"], "parsed")
        self.assertEqual(item["registers"], ["v0", "v1", "v2"])
        self.assertTrue(item["invoke_static"])
        self.assertEqual(item["ref"]["descriptor"],
                         "([Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")

    def test_invoke_interface_is_instance_call(self):
        item = SP.parse_line("    invoke-interface {v0, v1}, Lx/I;->run(I)V")
        self.assertEqual(item["status"], "parsed")
        self.assertFalse(item["invoke_static"])

    def test_zero_arg_invoke_allows_empty_register_list(self):
        item = SP.parse_line("    invoke-static {}, Lx/Util;->init()V")
        self.assertEqual(item["status"], "parsed")
        self.assertEqual(item["registers"], [])
        self.assertTrue(item["invoke_static"])

    def test_invoke_trailing_comment_parsed(self):
        item = SP.parse_line("    invoke-virtual {p0, v0}, Lx/A;->m()V  # note")
        self.assertEqual(item["status"], "parsed")
        self.assertEqual(item["ref"]["name"], "m")

    def test_move_result_variants(self):
        for op in ("move-result", "move-result-object", "move-result-wide"):
            with self.subTest(op=op):
                item = SP.parse_line(f"    {op} v3")
                self.assertEqual(item["status"], "parsed")
                self.assertEqual(item["opcode"], op)
                self.assertEqual(item["registers"], ["v3"])
                self.assertIsNone(item["invoke_static"])

    def test_move_two_register_forms(self):
        for line, want in (
            ("    move-object/from16 v0, v1", ["v0", "v1"]),
            ("    move/16 v10, v11", ["v10", "v11"]),
            ("    move-wide v0, v2", ["v0", "v2"]),
        ):
            with self.subTest(line=line):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "parsed")
                self.assertEqual(item["registers"], want)

    def test_const_family_register_parsing(self):
        for line, op in (
            ("    const/4 v0, 0x1", "const/4"),
            ("    const-wide/high16 v2, 0x0", "const-wide/high16"),
            ('    const-string v1, "safe"', "const-string"),
            ('    const-string/jumbo v1, "long"', "const-string/jumbo"),
            ("    const-class v0, Lx/Y;", "const-class"),
            ("    const-method-handle v0, Lx;->m()V", "const-method-handle"),
        ):
            with self.subTest(op=op):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "parsed")
                self.assertEqual(item["opcode"], op)
                self.assertTrue(item["registers"], f"no register for {op}")

    def test_new_instance_and_new_array(self):
        item = SP.parse_line("    new-instance v0, Lx/Y;")
        self.assertEqual((item["status"], item["registers"]), ("parsed", ["v0"]))
        item = SP.parse_line("    new-array v0, v1, [B")
        self.assertEqual((item["status"], item["registers"]), ("parsed", ["v0", "v1"]))

    def test_aget_family_and_fill_array_data(self):
        item = SP.parse_line("    aget-object v0, v1, v2")
        self.assertEqual((item["status"], item["registers"]),
                         ("parsed", ["v0", "v1", "v2"]))
        item = SP.parse_line("    aget-wide v0, v1, v2")
        self.assertEqual((item["status"], item["opcode"]),
                         ("parsed", "aget-wide"))
        item = SP.parse_line("    fill-array-data v0, :array_0")
        self.assertEqual((item["status"], item["registers"]), ("parsed", ["v0"]))


class TestIrrelevant(unittest.TestCase):
    def test_non_instruction_lines_are_irrelevant(self):
        for line in ("", "    ", "    # comment", "    :cond_0",
                     "    .locals 2", ".method public go()V",
                     "    .end method"):
            with self.subTest(line=line):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "irrelevant", line)
                self.assertEqual(item["reason"], "")
                self.assertEqual(item["registers"], [])

    def test_no_value_effect_opcodes_are_irrelevant_not_gaps(self):
        for line, op in (
            ("    nop", "nop"),
            ("    return-void", "return-void"),
            ("    return-object v0", "return-object"),
            ("    throw v1", "throw"),
            ("    goto :goto_0", "goto"),
            ("    if-eqz v0, :cond_0", "if-eqz"),
            ("    packed-switch v0, :pswitch_data_0", "packed-switch"),
            ("    check-cast v0, Lx/Y;", "check-cast"),
            ("    monitor-enter v0", "monitor-enter"),
        ):
            with self.subTest(op=op):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "irrelevant", op)
                self.assertEqual(item["opcode"], op)
                self.assertEqual(item["reason"], "")


class TestUnsupported(unittest.TestCase):
    def test_unmodeled_opcode_is_unsupported_not_parsed(self):
        for line, tok in (
            ("    invoke-custom {v0}, Lx;->f()V", "invoke-custom"),
            ("    invoke-polymorphic {v0}, Lx;->f()V, ()V", "invoke-polymorphic"),
            ("    execute-inline {v0}, Lx;->f()V", "execute-inline"),
        ):
            with self.subTest(op=tok):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "unsupported", line)
                self.assertEqual(item["opcode"], tok)
                self.assertIn(tok, item["reason"])
                self.assertEqual(item["registers"], [])
                self.assertIsNone(item["ref"])

    def test_unknown_opcode_token_is_unsupported(self):
        item = SP.parse_line("    frobnicate v0")
        self.assertEqual(item["status"], "unsupported")
        self.assertIn("frobnicate", item["reason"])


class TestMalformed(unittest.TestCase):
    def test_operand_failures_are_malformed(self):
        for line in (
            "    move v0",                       # missing source register
            "    move-result",                   # missing register
            "    const/4 v0,",                   # missing literal
            "    const-string v0, unquoted",     # unquoted string
            "    invoke-virtual {v0, x1}, Lx/Y;->m()V",  # bad register token
        ):
            with self.subTest(line=line):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "malformed", line)
                self.assertTrue(item["reason"], f"no reason for {line!r}")
                self.assertEqual(item["registers"], [])

    def test_non_instruction_garbage_is_malformed(self):
        for line in ("   @@@ nope", "    {v0}", "    0x12 0x34"):
            with self.subTest(line=line):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "malformed", line)
                self.assertTrue(item["reason"])

    def test_categories_are_distinct(self):
        got = {
            SP.parse_line("    invoke-custom {v0}, Lx;->f()V")["status"],
            SP.parse_line("    move v0")["status"],
            SP.parse_line("    nop")["status"],
        }
        self.assertEqual(got, {"unsupported", "malformed", "irrelevant"})


class TestExpandedGrammar(unittest.TestCase):
    def test_field_access_is_parsed(self):
        cases = (
            ("    iget-object v0, p0, Lx;->f:Ljava/lang/String;",
             "iget-object", ["v0", "p0"]),
            ("    iput-object v0, p0, Lx;->f:Ljava/lang/String;",
             "iput-object", ["v0", "p0"]),
            ("    sget-object v1, Lx;->a:Ljava/lang/String;",
             "sget-object", ["v1"]),
            ("    sput-object v1, Lx;->a:Ljava/lang/String;",
             "sput-object", ["v1"]),
            ("    iget-wide v0, p0, Lx;->d:J", "iget-wide", ["v0", "p0"]),
        )
        for line, tok, regs in cases:
            with self.subTest(op=tok):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "parsed", line)
                self.assertEqual(item["opcode"], tok)
                self.assertEqual(item["registers"], regs)

    def test_field_reference_captured(self):
        item = SP.parse_line("    sget-object v1, Lx;->a:Ljava/lang/String;")
        self.assertEqual(item["ref"], {
            "owner": "Lx;", "name": "a", "descriptor": "Ljava/lang/String;"})

    def test_arithmetic_and_conversions_are_parsed(self):
        cases = (
            ("    add-int v0, v1, v2", "add-int", ["v0", "v1", "v2"]),
            ("    add-int/2addr v0, v1", "add-int/2addr", ["v0", "v1"]),
            ("    add-int/lit8 v0, v1, 0x1", "add-int/lit8", ["v0", "v1"]),
            ("    mul-long v0, v2, v4", "mul-long", ["v0", "v2", "v4"]),
            ("    rem-int v0, v1, v2", "rem-int", ["v0", "v1", "v2"]),
            ("    int-to-long v0, v0", "int-to-long", ["v0", "v0"]),
            ("    neg-int v0, v1", "neg-int", ["v0", "v1"]),
            ("    cmp-long v0, v1, v2", "cmp-long", ["v0", "v1", "v2"]),
            ("    array-length v0, v1", "array-length", ["v0", "v1"]),
            ("    instance-of v0, v1, Ljava/lang/String;",
             "instance-of", ["v0", "v1"]),
        )
        for line, tok, regs in cases:
            with self.subTest(op=tok):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "parsed", line)
                self.assertEqual(item["opcode"], tok)
                self.assertEqual(item["registers"], regs)

    def test_array_ops_are_parsed(self):
        for line, tok in (
            ("    aput-object v0, v1, v2", "aput-object"),
            ("    aput v0, v1, v2", "aput"),
            ("    filled-new-array {v0, v1}, [I", "filled-new-array"),
            ("    filled-new-array/range {p0 .. p2}, [Ljava/lang/String;",
             "filled-new-array/range"),
        ):
            with self.subTest(op=tok):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "parsed", line)
                self.assertEqual(item["opcode"], tok)

    def test_move_exception_is_parsed_single_register(self):
        item = SP.parse_line("    move-exception v0")
        self.assertEqual(item["status"], "parsed")
        self.assertEqual(item["opcode"], "move-exception")
        self.assertEqual(item["registers"], ["v0"])

    def test_bad_field_operands_are_malformed(self):
        for line in (
            "    iget-object v0, p0",                 # missing field ref
            "    sget-object v1",                     # missing field ref
            "    iget-object v0, v1, notafield",      # bad field token
        ):
            with self.subTest(line=line):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "malformed", line)
                self.assertTrue(item["reason"])

    def test_data_block_lines_are_irrelevant_not_malformed(self):
        body = [
            "    .array-data 4",
            "        0x1",
            "        0x2",
            "    .end array-data",
            "    .annotation runtime Lx/Ann;",
            "        value = \"x\"",
            "    .end annotation",
            "    nop",
        ]
        items = SP.parse_lines(body)
        self.assertEqual([i["status"] for i in items],
                         ["irrelevant"] * 7 + ["irrelevant"])
        self.assertEqual(items[-1]["opcode"], "nop")
        # nothing inside the blocks was counted as a syntax gap
        self.assertEqual(
            [i["status"] for i in items].count("malformed"), 0)
        self.assertEqual(
            [i["status"] for i in items].count("unsupported"), 0)

    def test_block_annotations_inside_method_are_irrelevant(self):
        body = [
            "    .annotation build Lx/Keep;",
            "    .end annotation",
            "    invoke-virtual {p0}, Lx;->run()V",
        ]
        items = SP.parse_lines(body)
        self.assertEqual(items[0]["status"], "irrelevant")
        self.assertEqual(items[1]["status"], "irrelevant")
        self.assertEqual(items[2]["status"], "parsed")
        self.assertEqual(items[2]["opcode"], "invoke-virtual")

    def test_rsub_int_lit8_is_parsed(self):
        item = SP.parse_line("    rsub-int/lit8 v5, v0, 0xe")
        self.assertEqual(item["status"], "parsed")
        self.assertEqual(item["opcode"], "rsub-int/lit8")
        self.assertEqual(item["registers"], ["v5", "v0"])

    def test_array_typed_invoke_owner_is_parsed(self):
        for line, owner in (
            ("    invoke-virtual {v0}, [Lapp/fast/ssh/X;->clone()Ljava/lang/Object;",
             "[Lapp/fast/ssh/X;"),
            ("    invoke-virtual {v0}, [I->clone()Ljava/lang/Object;", "[I"),
        ):
            with self.subTest(owner=owner):
                item = SP.parse_line(line)
                self.assertEqual(item["status"], "parsed", line)
                self.assertEqual(item["ref"]["owner"], owner)
                self.assertEqual(item["ref"]["name"], "clone")

    def test_switch_payload_rows_are_irrelevant(self):
        body = [
            "    sparse-switch v0, :sswitch_data_0",
            "    :sswitch_data_0",
            "    .sparse-switch",
            "        0x7f09005a -> :sswitch_7",
            "        0x7f0900f2 -> :sswitch_5",
            "    .end sparse-switch",
            "    .packed-switch 0x0",
            "        :pswitch_0",
            "    .end packed-switch",
        ]
        items = SP.parse_lines(body)
        self.assertEqual(
            [i["status"] for i in items].count("malformed"), 0)
        self.assertEqual(
            [i["status"] for i in items].count("unsupported"), 0)
        self.assertEqual(items[2]["status"], "irrelevant")
        self.assertEqual(items[3]["status"], "irrelevant")


class TestContract(unittest.TestCase):
    def test_line_numbers_assigned(self):
        items = SP.parse_lines(["    nop", "    move v0, v1"], start=5)
        self.assertEqual([i["line"] for i in items], [5, 6])
        items = SP.parse_lines(["    nop"])
        self.assertEqual(items[0]["line"], 0)

    def test_canonical_invoke_output_is_stable(self):
        raw = "    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"
        self.assertEqual(SP.parse_line(raw, 7), {
            "line": 7,
            "raw": raw,
            "status": "parsed",
            "opcode": "invoke-virtual",
            "registers": ["p0", "v0"],
            "ref": {"owner": "Landroid/webkit/WebView;",
                    "name": "loadUrl",
                    "descriptor": "(Ljava/lang/String;)V"},
            "reason": "",
            "invoke_static": False,
        })

    def test_method_declaration_helper(self):
        self.assertEqual(SP.method_declaration("public static go(Ljava/lang/String;)V"),
                         ("go", "(Ljava/lang/String;)V"))
        self.assertEqual(SP.method_declaration("public <init>()V"), ("<init>", "()V"))
        self.assertEqual(SP.method_declaration("public go(I)V # trailing"),
                         ("go", "(I)V"))
        self.assertIsNone(SP.method_declaration("public"))
        self.assertIsNone(SP.method_declaration(""))

    def test_method_declaration_hyphenated_name_not_truncated(self):
        self.assertEqual(SP.method_declaration("public foo-bar(I)V"),
                         ("foo-bar", "(I)V"))

    def test_method_declaration_midtoken_garbage_rejected(self):
        self.assertIsNone(SP.method_declaration("public foo+bar(I)V"))


if __name__ == "__main__":
    unittest.main()
