"""Browser extension/native-host boundary tests (no real browser required)."""
from __future__ import annotations

import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.browser_context import BrowserContextCollector


class _Edr:
    def __init__(self) -> None:
        self.events = []

    def ingest_telemetry(self, event) -> None:
        self.events.append(event)


class BrowserContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.edr = _Edr()
        self.collector = BrowserContextCollector(
            self.edr, token_path=Path(self.temp.name) / "browser-token.txt",
            token="t" * 32)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _event(self, **extra):
        event = {
            "version": 1,
            "event_type": "form_submit",
            "url": "https://example.test/account?email=private@example.test",
            "tab_id": 41,
            "frame_id": 0,
            "user_initiated": True,
            "gesture": "submit",
            "consent_state": "unknown",
            "browser": "chromium",
        }
        event.update(extra)
        return event

    def test_sanitizes_to_origin_and_emits_privacy_telemetry(self):
        result = self.collector.ingest(self._event())
        self.assertTrue(result["accepted"])
        self.assertEqual(result["event"]["first_party_origin"], "https://example.test")
        self.assertEqual(len(self.edr.events), 1)
        telemetry = self.edr.events[0]
        self.assertEqual(telemetry.category, "privacy")
        encoded = str(telemetry.to_dict())
        self.assertNotIn("private@example.test", encoded)
        self.assertNotIn("/account", encoded)
        self.assertEqual(telemetry.fields["browser_event_type"], "form_submit")

    def test_rejects_invalid_and_oversized_messages(self):
        self.assertFalse(self.collector.ingest(self._event(url="file:///private.txt"))["accepted"])
        self.assertFalse(self.collector.ingest(self._event(extra="x" * 20000))["accepted"])
        self.assertEqual(self.collector.status()["rejected"], 2)
        self.assertEqual(self.edr.events, [])

    def test_token_is_required_and_constant_boundary_is_exposed(self):
        token = "t" * 32
        self.assertTrue(self.collector.token_ok(token))
        self.assertFalse(self.collector.token_ok("wrong"))
        self.assertIn("raw values are transient", self.collector.status()["privacy_boundary"])

    def test_scoped_gesture_authorizes_one_matching_submit(self):
        interaction = str(uuid.uuid4())
        gesture = self._event(
            event_type="user_gesture", gesture="pointer",
            interaction_id=interaction, intended_action="form_submit",
            destination_origin="https://receiver.test/upload?ignored=yes",
            data_labels=["email", "ordinary"],
        )
        issued = self.collector.ingest(gesture)
        self.assertEqual(issued["event"]["authority"]["disposition"], "issued")

        submit = self._event(
            interaction_id=interaction,
            destination_origin="https://receiver.test/collect?secret=never-retain",
            data_labels=["email"],
        )
        allowed = self.collector.ingest(submit)
        self.assertEqual(allowed["event"]["authority"]["disposition"], "allow")
        self.assertFalse(allowed["event"]["authority"]["enforced"])

        replay = self.collector.ingest(submit)
        self.assertEqual(replay["event"]["authority"]["disposition"], "refuse")

    def test_raw_payload_fields_never_cross_sanitizer_or_telemetry(self):
        secret = "raw-secret-4f902a74"
        result = self.collector.ingest(self._event(
            raw_form_value=secret,
            page_text=secret,
            cookie=secret,
            data_labels=["email", secret],
            destination_origin="https://receiver.test/path?q=" + secret,
        ))
        encoded = str(result) + str(self.collector.status()) + str(
            [event.to_dict() for event in self.edr.events])
        self.assertNotIn(secret, encoded)
        self.assertEqual(result["event"]["destination_origin"], "https://receiver.test")

    def test_unverifiable_token_file_fails_closed(self):
        token_path = Path(self.temp.name) / "unverifiable-token.txt"
        with patch("valkyrie.secure_file.harden", return_value=(False, "ACL failed")), \
             patch("valkyrie.secure_file.verify", return_value=(False, "ACL failed")):
            collector = BrowserContextCollector(self.edr, token_path=token_path)
        self.assertFalse(collector.status()["native_host_ready"])
        self.assertFalse(token_path.exists())

    def test_loopback_api_requires_bridge_token(self):
        try:
            from valkyrie.context import AppContext
            from valkyrie.web.server import create_app
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from testclient_compat import make_client
        except ImportError as exc:
            self.skipTest(str(exc))
        app = create_app(AppContext(browser_context=self.collector, ready=True))
        client = make_client(app, "127.0.0.1")
        self.assertEqual(client.post("/api/browser/events", json=self._event()).status_code, 403)
        token = "t" * 32
        response = client.post("/api/browser/events", json=self._event(),
                               headers={"X-Valkyrie-Browser-Token": token})
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json()["accepted"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("PASS" if result.wasSuccessful() else "FAIL")
    raise SystemExit(0 if result.wasSuccessful() else 1)
