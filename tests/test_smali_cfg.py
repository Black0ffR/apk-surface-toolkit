"""Stage 2 (TF-02) tests: basic-block CFG over smali method bodies.

Blocks split at labels, after terminators (goto/if/switch/return/throw), and
around packed/sparse payload spans; unresolved targets are accounted, never
invented. In-memory bodies only; no APK execution.
"""
from __future__ import annotations

import unittest

from triagekit import smali_cfg as CFG


class TestBlocks(unittest.TestCase):
    def test_empty_body(self):
        cfg = CFG.build([])
        self.assertEqual(cfg.blocks, ())
        self.assertEqual(cfg.entry, "")
        self.assertEqual(cfg.missing_labels, ())
        self.assertEqual(cfg.unresolved_switches, 0)

    def test_straight_line_is_one_block(self):
        body = [
            "    .locals 2",
            "    invoke-virtual {p0}, Lx/In;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
            "    move-result-object v0",
            "    invoke-virtual {p0, v0}, Lx/WebView;->loadUrl(Ljava/lang/String;)V",
            "    return-void",
        ]
        cfg = CFG.build(body)
        self.assertEqual(len(cfg.blocks), 1)
        b = cfg.blocks[0]
        self.assertEqual((b.start_line, b.end_line), (0, 4))
        self.assertEqual(b.terminator, "return")
        self.assertEqual(b.successors, ())
        self.assertEqual(b.labels, ())
        self.assertEqual(cfg.entry, b.block_id)
        self.assertEqual(cfg.missing_labels, ())
        self.assertEqual(cfg.unresolved_switches, 0)

    def test_label_splits_blocks_and_if_edges(self):
        body = [
            "    const/4 v0, 0x0",
            "    if-eqz v0, :skip",
            "    return-void",
            ":skip",
            "    return-void",
        ]
        cfg = CFG.build(body)
        self.assertEqual(len(cfg.blocks), 3)
        b0, b1, b2 = cfg.blocks
        self.assertEqual((b0.start_line, b0.end_line), (0, 1))
        self.assertEqual(b0.terminator, "if")
        self.assertEqual(b0.successors, (b1.block_id, b2.block_id))
        self.assertEqual(b1.terminator, "return")
        self.assertEqual(b2.labels, ("skip",))
        self.assertEqual(cfg.label_to_block["skip"], b2.block_id)

    def test_hyphenated_labels_do_not_collide(self):
        body = [
            "    if-eqz v0, :cond-a",
            "    goto :cond-b",
            ":cond-a",
            "    return-void",
            ":cond-b",
            "    return-void",
        ]
        cfg = CFG.build(body)
        self.assertIn("cond-a", cfg.label_to_block)
        self.assertIn("cond-b", cfg.label_to_block)
        self.assertNotEqual(cfg.label_to_block["cond-a"],
                            cfg.label_to_block["cond-b"])
        self.assertEqual(cfg.missing_labels, ())

    def test_goto_missing_label_is_accounted_not_invented(self):
        body = ["    goto :nowhere", "    return-void"]
        cfg = CFG.build(body)
        b0, b1 = cfg.blocks
        self.assertEqual(b0.terminator, "goto")
        self.assertEqual(b0.successors, ())
        self.assertEqual(b0.missing_targets, ("nowhere",))
        self.assertEqual(cfg.missing_labels, ("nowhere",))
        self.assertNotIn(b1.block_id, b0.successors)

    def test_missing_labels_are_sorted_and_deduped(self):
        body = ["    if-eqz v0, :b", "    goto :a", "    goto :b"]
        cfg = CFG.build(body)
        self.assertEqual(cfg.missing_labels, ("a", "b"))

    def test_consecutive_labels_share_one_block(self):
        body = [":a", ":b", "    return-void"]
        cfg = CFG.build(body)
        self.assertEqual(len(cfg.blocks), 1)
        self.assertEqual(cfg.blocks[0].labels, ("a", "b"))
        self.assertEqual(cfg.label_to_block["a"], cfg.label_to_block["b"])

    def test_throw_terminates_without_successor(self):
        body = ["    throw v0"]
        cfg = CFG.build(body)
        self.assertEqual(cfg.blocks[0].terminator, "throw")
        self.assertEqual(cfg.blocks[0].successors, ())

    def test_trailing_label_without_instruction(self):
        body = ["    return-void", ":end"]
        cfg = CFG.build(body)
        self.assertEqual(len(cfg.blocks), 2)
        self.assertEqual(cfg.blocks[1].labels, ("end",))
        self.assertEqual(cfg.blocks[1].terminator, "end")

    def test_branch_to_next_instruction_dedupes_edge(self):
        body = ["    if-eqz v0, :same", ":same", "    return-void"]
        cfg = CFG.build(body)
        b0, b1 = cfg.blocks
        self.assertEqual(b0.successors, (b1.block_id,))


class TestSwitch(unittest.TestCase):
    def test_packed_switch_resolves_case_labels(self):
        body = [
            "    packed-switch v0, :pswitch_data_0",
            ":case_a",
            "    return-void",
            ":case_b",
            "    return-void",
            ":pswitch_data_0",
            "    .packed-switch 0x0",
            "        :case_a",
            "        :case_b",
            "    .end packed-switch",
        ]
        cfg = CFG.build(body)
        b0 = cfg.blocks[0]
        self.assertEqual(b0.terminator, "switch")
        self.assertEqual(b0.successors,
                         (cfg.label_to_block["case_a"],
                          cfg.label_to_block["case_b"]))
        self.assertEqual(cfg.unresolved_switches, 0)
        payload = [b for b in cfg.blocks if b.terminator == "payload"]
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0].payload_targets, ("case_a", "case_b"))
        self.assertEqual(payload[0].labels, ("pswitch_data_0",))

    def test_sparse_switch_reads_arrow_labels(self):
        body = [
            "    sparse-switch v0, :sswitch_data_0",
            ":t1",
            "    return-void",
            ":t2",
            "    return-void",
            ":sswitch_data_0",
            "    .sparse-switch",
            "        0x0 -> :t1",
            "        0x1 -> :t2",
            "    .end sparse-switch",
        ]
        cfg = CFG.build(body)
        b0 = cfg.blocks[0]
        self.assertEqual(b0.successors,
                         (cfg.label_to_block["t1"], cfg.label_to_block["t2"]))

    def test_unresolved_payload_label_is_a_gap(self):
        body = [
            "    packed-switch v0, :pswitch_data_0",
            ":other",
            "    return-void",
        ]
        cfg = CFG.build(body)
        b0 = cfg.blocks[0]
        self.assertEqual(b0.successors, ())
        self.assertEqual(cfg.unresolved_switches, 1)
        self.assertIn("pswitch_data_0", cfg.missing_labels)

    def test_payload_without_case_labels_is_unresolved(self):
        body = [
            "    packed-switch v0, :d",
            ":d",
            "    .packed-switch 0x0",
            "    .end packed-switch",
        ]
        cfg = CFG.build(body)
        self.assertEqual(cfg.blocks[0].terminator, "switch")
        self.assertEqual(cfg.blocks[0].successors, ())
        self.assertEqual(cfg.unresolved_switches, 1)

    def test_case_label_without_block_is_missing_not_invented(self):
        body = [
            "    packed-switch v0, :d",
            ":d",
            "    .packed-switch 0x0",
            "        :ghost",
            "    .end packed-switch",
        ]
        cfg = CFG.build(body)
        self.assertEqual(cfg.blocks[0].successors, ())
        self.assertIn("ghost", cfg.missing_labels)
        self.assertEqual(cfg.unresolved_switches, 0)

    def test_switch_has_no_fallthrough(self):
        body = [
            "    packed-switch v0, :d",
            "    return-void",
            ":d",
            "    .packed-switch 0x0",
            "        :case_a",
            "    .end packed-switch",
            ":case_a",
            "    return-void",
        ]
        cfg = CFG.build(body)
        b0, b1 = cfg.blocks[0], cfg.blocks[1]
        self.assertEqual(b0.successors, (cfg.label_to_block["case_a"],))
        self.assertNotIn(b1.block_id, b0.successors)


class TestDeterminism(unittest.TestCase):
    def test_two_builds_are_identical(self):
        body = [
            "    const/4 v0, 0x0",
            "    if-eqz v0, :skip",
            "    goto :missing",
            ":skip",
            "    packed-switch v0, :d",
            ":d",
            "    .packed-switch 0x0",
            "        :case_a",
            "    .end packed-switch",
            ":case_a",
            "    return-void",
        ]
        a = CFG.build(list(body))
        b = CFG.build(list(body))
        self.assertEqual(a, b)
        self.assertEqual([bl.block_id for bl in a.blocks],
                         [bl.block_id for bl in b.blocks])


if __name__ == "__main__":
    unittest.main()
