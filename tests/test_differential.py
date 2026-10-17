"""DT-01: deterministic differential harness tests (plan §16).

Synthetic corpora and pure in-process callables only. No subprocesses,
no native loading, no APK execution, no network.
"""

import hashlib
import signal
import time
import unittest

from triagekit import differential as DIFF


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestCompareOutputs(unittest.TestCase):
    def test_match_and_mismatch_status(self):
        cases = [b"aa", b"bb"]
        ref = lambda d: d.upper()
        cand = lambda d: b"XX" if d == b"bb" else b"AA"
        results = DIFF.compare_outputs(cases, ref, cand)
        self.assertEqual([r["status"] for r in results], ["match", "mismatch"])
        self.assertTrue(results[0]["equal"])
        self.assertFalse(results[1]["equal"])

    def test_hashes_recorded(self):
        results = DIFF.compare_outputs([b"abc"], lambda d: d, lambda d: d)
        r = results[0]
        self.assertEqual(r["input_sha256"], _sha(b"abc"))
        self.assertEqual(r["reference_sha256"], _sha(b"abc"))
        self.assertEqual(r["candidate_sha256"], _sha(b"abc"))
        self.assertEqual(r["input_length"], 3)
        self.assertIsInstance(r["elapsed_ms"]["total"], float)

    def test_oversized_input_skipped_without_truncation(self):
        calls = []

        def ref(d):
            calls.append(("ref", len(d)))
            return d

        def cand(d):
            calls.append(("cand", len(d)))
            return d

        big = b"x" * 64
        results = DIFF.compare_outputs([big], ref, cand, max_case_bytes=16)
        self.assertEqual(results[0]["status"], "skipped")
        self.assertIsNone(results[0]["equal"])
        self.assertEqual(calls, [])
        self.assertEqual(results[0]["input_length"], 64)
        self.assertIn("64", results[0]["reason"])
        self.assertIn("16", results[0]["reason"])

    def test_reference_exception_is_failure_not_mismatch(self):
        calls = []

        def ref(d):
            raise ValueError("boom")

        def cand(d):
            calls.append(len(d))
            return d

        results = DIFF.compare_outputs([b"a"], ref, cand)
        r = results[0]
        self.assertEqual(r["status"], "failure")
        self.assertIsNone(r["equal"])
        self.assertEqual(r["error"]["phase"], "reference")
        self.assertEqual(r["error"]["type"], "ValueError")
        self.assertEqual(calls, [], "candidate must not run when reference fails")

    def test_candidate_exception_records_phase_and_reference_hash(self):
        results = DIFF.compare_outputs([b"a"], lambda d: d,
                                       lambda d: 1 / 0)
        r = results[0]
        self.assertEqual(r["status"], "failure")
        self.assertEqual(r["error"]["phase"], "candidate")
        self.assertEqual(r["error"]["type"], "ZeroDivisionError")
        self.assertEqual(r["reference_sha256"], _sha(b"a"))
        self.assertIsNone(r["candidate_sha256"])

    def test_case_identities_stable_across_runs(self):
        cases = [b"", b"1", b"22"]
        args = (cases, lambda d: d, lambda d: d)
        first = DIFF.compare_outputs(*args)
        second = DIFF.compare_outputs(*args)
        ids_1 = [r["case_id"] for r in first]
        ids_2 = [r["case_id"] for r in second]
        self.assertEqual(ids_1, ids_2)
        self.assertEqual(len(set(ids_1)), 3)

    def test_non_bytes_input_rejected(self):
        with self.assertRaises(TypeError):
            DIFF.compare_outputs(["text"], lambda d: d, lambda d: d)

    def test_no_plaintext_input_stored(self):
        results = DIFF.compare_outputs([b"secret-value"], lambda d: d,
                                       lambda d: d)
        self.assertNotIn("input", results[0])
        self.assertNotIn("data", results[0])

    def test_mismatch_minimization(self):
        data = b"A" * 16
        ref = lambda d: d
        cand = lambda d: b"" if b"A" in d else d
        results = DIFF.compare_outputs([data], ref, cand, minimize=True)
        r = results[0]
        self.assertEqual(r["status"], "mismatch")
        minimized = r["minimized"]
        self.assertIsNotNone(minimized)
        self.assertLessEqual(minimized["input_length"], len(data))
        self.assertEqual(minimized["input_sha256"], _sha(b"A"))
        self.assertGreaterEqual(minimized["rounds"], 1)

    def test_minimization_returns_original_when_not_reproducible(self):
        minimized, rounds = DIFF.minimize_mismatch(
            b"zzz", lambda d: d, lambda d: d)
        self.assertEqual(minimized, b"zzz")
        self.assertEqual(rounds, 0)

    def test_equal_is_none_for_skipped_and_failure(self):
        results = DIFF.compare_outputs(
            [b"toolong", b"x"], lambda d: (_ for _ in ()).throw(OSError()),
            lambda d: d, max_case_bytes=3)
        self.assertIsNone(results[0]["equal"])
        self.assertIsNone(results[1]["equal"])


class TestTimeout(unittest.TestCase):
    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "needs SIGALRM")
    def test_timeout_recorded_as_failure(self):
        results = DIFF.compare_outputs(
            [b"x"], lambda d: d, lambda d: time.sleep(1.5) or d,
            max_seconds_per_case=0.05)
        r = results[0]
        self.assertEqual(r["status"], "failure")
        self.assertEqual(r["error"]["type"], "timeout")
        self.assertEqual(r["error"]["phase"], "candidate")


class TestSummary(unittest.TestCase):
    def test_conclusion_language_not_full_equivalence(self):
        results = DIFF.compare_outputs([b"a", b"b"],
                                       lambda d: d, lambda d: d)
        summary = DIFF.equivalence_summary(
            results, reference_label="ref.py",
            candidate_label="candidate.py", corpus_label="unit")
        self.assertEqual(summary["conclusion"], "matches-tested-corpus")
        self.assertNotIn("equivalent", summary["conclusion"])
        self.assertEqual(summary["reference_label"], "ref.py")
        self.assertEqual(summary["candidate_label"], "candidate.py")
        joined = " ".join(summary["limitations"])
        self.assertIn("tested corpus", joined)
        self.assertEqual(summary["counts"]["match"], 2)

    def test_mismatch_and_incomplete_conclusions(self):
        mismatch = DIFF.compare_outputs([b"a"], lambda d: d,
                                        lambda d: b"z")
        summary = DIFF.equivalence_summary(mismatch)
        self.assertEqual(summary["conclusion"], "divergences-found")
        failure = DIFF.compare_outputs([b"a"],
                                       lambda d: (_ for _ in ()).throw(OSError()),
                                       lambda d: d)
        summary = DIFF.equivalence_summary(failure)
        self.assertEqual(summary["conclusion"], "incomplete-corpus")

    def test_empty_corpus_is_inconclusive_not_success(self):
        summary = DIFF.equivalence_summary([])
        self.assertEqual(summary["counts"]["total"], 0)
        self.assertEqual(summary["conclusion"], "inconclusive-empty-corpus")

    def test_case_identities_listed(self):
        results = DIFF.compare_outputs([b"a"], lambda d: d, lambda d: d)
        summary = DIFF.equivalence_summary(results)
        self.assertEqual(summary["case_ids"], [results[0]["case_id"]])


class TestDefaultCorpus(unittest.TestCase):
    def test_deterministic_and_covers_documented_shapes(self):
        first = DIFF.default_corpus()
        second = DIFF.default_corpus()
        self.assertEqual(first, second)
        self.assertIn(b"", first)
        self.assertIn(b"\x00", first)
        self.assertIn(b"\xff", first)
        lengths = {len(c) for c in first}
        self.assertTrue(any(l == 16 for l in lengths), lengths)
        self.assertTrue(any(l == 15 or l == 17 for l in lengths), lengths)
        self.assertTrue(max(lengths) >= 1024)
        self.assertTrue(any(c == c[:1] * len(c) and len(c) > 1
                            for c in first if c))


if __name__ == "__main__":
    unittest.main()
