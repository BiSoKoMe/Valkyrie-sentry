"""Deterministic causal-authority tests with no browser or network required."""
from __future__ import annotations

import sys
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.causal_authority import (CausalAuthorityEngine, EgressRequest,
                                       EgressDisposition)


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class CausalAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _Clock()
        self.engine = CausalAuthorityEngine(clock=self.clock, ttl_s=2.0)
        self.interaction = str(uuid.uuid4())

    def _issue(self, **changes):
        values = {
            "interaction_id": self.interaction,
            "source_origin": "https://shop.example",
            "destination_origin": "https://payments.example",
            "tab_id": 7,
            "frame_id": 0,
            "action": "form_submit",
            "data_labels": ["email", "payment"],
        }
        values.update(changes)
        return self.engine.issue(**values)

    def _request(self, **changes) -> EgressRequest:
        values = {
            "request_id": str(uuid.uuid4()),
            "interaction_id": self.interaction,
            "source_origin": "https://shop.example",
            "destination_origin": "https://payments.example",
            "tab_id": 7,
            "frame_id": 0,
            "action": "form_submit",
            "data_labels": frozenset({"email", "payment"}),
        }
        values.update(changes)
        return EgressRequest(**values)

    def test_exact_scope_allows_once(self):
        self.assertIsNotNone(self._issue())
        verdict = self.engine.verify_and_consume(self._request())
        self.assertEqual(verdict.disposition, EgressDisposition.ALLOW)
        replay = self.engine.verify_and_consume(self._request())
        self.assertEqual(replay.disposition, EgressDisposition.REFUSE)
        self.assertIn("consumed", replay.reason)
        self.assertIsNone(self._issue())

    def test_destination_change_refuses_and_burns_grant(self):
        self._issue()
        changed = self.engine.verify_and_consume(
            self._request(destination_origin="https://collector.example"))
        self.assertFalse(changed.allowed)
        self.assertIn("destination", changed.reason)
        self.assertFalse(self.engine.verify_and_consume(self._request()).allowed)

    def test_new_sensitive_label_after_gesture_refuses(self):
        self._issue(data_labels=["ordinary"])
        verdict = self.engine.verify_and_consume(
            self._request(data_labels=frozenset({"ordinary", "credential"})))
        self.assertFalse(verdict.allowed)
        self.assertIn("gained data labels", verdict.reason)

    def test_expired_and_missing_grants_refuse(self):
        self._issue()
        self.clock.now += 2.01
        self.assertFalse(self.engine.verify_and_consume(self._request()).allowed)
        missing = self.engine.verify_and_consume(
            self._request(interaction_id=str(uuid.uuid4())))
        self.assertFalse(missing.allowed)
        self.assertIn("no live", missing.reason)

    def test_malformed_or_empty_scope_never_issues(self):
        self.assertIsNone(self._issue(interaction_id="not-a-uuid"))
        self.assertIsNone(self._issue(data_labels=[]))
        self.assertIsNone(self._issue(action="network_request"))
        self.assertIsNone(self._issue(destination_origin="file:///private.txt"))

    def test_reissuing_one_interaction_cannot_hide_an_expired_grant(self):
        first_interaction = self.interaction
        self._issue()
        self.clock.now += 1.0
        other_interaction = str(uuid.uuid4())
        self.interaction = other_interaction
        self._issue()
        self.clock.now += 0.5
        self.interaction = first_interaction
        self._issue()
        self.clock.now += 1.6
        self.interaction = other_interaction
        expired = self.engine.verify_and_consume(self._request())
        self.assertFalse(expired.allowed)

    def test_reflex_path_is_small_and_local(self):
        samples = []
        for _ in range(1000):
            self.interaction = str(uuid.uuid4())
            start = time.perf_counter_ns()
            self._issue()
            verdict = self.engine.verify_and_consume(self._request())
            samples.append((time.perf_counter_ns() - start) / 1_000_000)
            self.assertTrue(verdict.allowed)
        samples.sort()
        p99 = samples[int(len(samples) * 0.99) - 1]
        # This is a regression tripwire, not a live browser latency claim.
        self.assertLess(p99, 10.0)


if __name__ == "__main__":
    unittest.main()
