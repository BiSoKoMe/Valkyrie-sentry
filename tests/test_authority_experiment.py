"""Regression tests for the admissions evidence experiment."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.authority_experiment import run_experiment


class AuthorityExperimentTests(unittest.TestCase):
    def test_small_corpus_passes_and_exposes_every_trial(self):
        evidence = run_experiment(authorized=24, unauthorized=16, max_p99_ms=50.0)
        self.assertTrue(evidence["passed"])
        self.assertEqual(evidence["metrics"]["correct"], 40)
        self.assertEqual(evidence["metrics"]["false_allows"], 0)
        self.assertEqual(evidence["metrics"]["false_refusals"], 0)
        self.assertEqual(len(evidence["records"]), 40)
        self.assertIn("expired", evidence["corpus"]["scenario_counts"])

    def test_evidence_never_contains_the_raw_sentinel(self):
        evidence = run_experiment(authorized=8, unauthorized=8, max_p99_ms=50.0)
        encoded = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("valkyrie-raw-sentinel-7f3c9a21", encoded)
        self.assertEqual(evidence["metrics"]["raw_sentinel_leaks"], 0)

    def test_threshold_failure_is_visible(self):
        evidence = run_experiment(authorized=2, unauthorized=2, max_p99_ms=0.0)
        self.assertFalse(evidence["passed"])
        self.assertFalse(evidence["criteria"]["in_process_p99_within_budget"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("PASS" if result.wasSuccessful() else "FAIL")
    raise SystemExit(0 if result.wasSuccessful() else 1)
