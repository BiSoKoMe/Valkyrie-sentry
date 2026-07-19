#!/usr/bin/env python3
"""AI assistant seam — offline tests with a fake Anthropic client.

The philosophy under test: AI explains, it never detects. The offline
heuristic analyst must always produce a complete report; Claude output is
additive, structured, evidence-grounded, and every failure mode falls back
cleanly.

  [1] Offline analyst always works (no key, no SDK, no network)
  [2] use_ai without a key -> ai_error + offline analysis intact
  [3] Structured AI analysis attached via a fake client; facts sent to the
      model are compact (no raw event dump) and the request uses structured
      output with the shipped-actions enum
  [4] Guard: schema-conforming reply with an unshipped action is rejected
  [5] Fake client raising -> ai_error fallback, report intact
"""

from __future__ import annotations

import json
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


class _FakeResp:
    def __init__(self, payload: dict) -> None:
        block = types.SimpleNamespace(type="text", text=json.dumps(payload))
        self.content = [block]


class _FakeClient:
    """Stands in for anthropic.Anthropic; records the request it received."""
    last_kwargs: dict = {}
    reply: dict = {}
    raise_on_call = False

    class _Messages:
        def create(self, **kwargs):
            _FakeClient.last_kwargs = kwargs
            if _FakeClient.raise_on_call:
                raise ConnectionError("network down")
            return _FakeResp(_FakeClient.reply)

    def __init__(self, *a, **k) -> None:
        self.messages = self._Messages()


def main() -> int:
    import os
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.edr.schema import Detection
    import valkyrie.edr.investigate as inv

    print("\n=== AI assistant seam (explain-only) ===\n")

    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "ai.db")
        store.start()
        engine = EdrEngine(store)
        engine.start()
        inc_id = engine.report_detection(Detection(
            source="test", severity="high", category="firewall_ip",
            title="connection to threat-intel IP", entity="evil.example",
            process_name="mal.exe", technique="T1071"))
        inc = engine._edr.get_incident(inc_id)
        dets = engine._edr.list_detections(incident_id=inc_id)
        investigator = inv.Investigator(engine._edr)

        print("[1] Offline analyst always works")
        rep = investigator.investigate(inc)
        _check("report produced with analyst=offline",
               rep["analyst"] == "offline" and rep["summary"])
        _check("recommended actions from shipped set",
               all(a["action"] in ("block_domain", "kill_process",
                                   "isolate_host")
                   for a in rep["recommended_actions"]))
        _check("MITRE technique surfaced", "T1071" in rep["techniques"])

        print("\n[2] use_ai without a key -> honest error + fallback")
        old_key = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_vk = os.environ.pop("VALKYRIE_AI_KEY", None)
        try:
            rep2 = investigator.investigate(inc, use_ai=True)
            _check("ai_error explains missing key",
                   "no API key" in rep2.get("ai_error", ""))
            _check("offline analysis still present", rep2["summary"])
            _check("analyst stays offline", rep2["analyst"] == "offline")
        finally:
            if old_key: os.environ["ANTHROPIC_API_KEY"] = old_key
            if old_vk: os.environ["VALKYRIE_AI_KEY"] = old_vk

        print("\n[3] Structured analysis via fake client")
        fake_mod = types.SimpleNamespace(Anthropic=_FakeClient)
        real_import = inv._ai_available
        inv._ai_available = lambda: True
        sys.modules["anthropic"] = fake_mod   # investigate imports lazily
        try:
            _FakeClient.reply = {
                "assessment": "mal.exe beaconed to evil.example, a known "
                              "threat-intel indicator.",
                "confidence": "high",
                "likely_technique": "T1071",
                "recommended_action": {"action": "kill_process",
                                       "target": "mal.exe",
                                       "rationale": "stop the beacon"},
                "evidence": ["connection to threat-intel IP"],
            }
            _FakeClient.raise_on_call = False
            rep3 = investigator.investigate(inc, use_ai=True)
            _check("analyst=claude with structured analysis",
                   rep3["analyst"] == "claude"
                   and rep3["ai_analysis"]["confidence"] == "high")
            _check("narrative mirrors assessment",
                   rep3["ai_narrative"].startswith("mal.exe beaconed"))
            sent = _FakeClient.last_kwargs
            body = sent["messages"][0]["content"]
            _check("structured output requested (json_schema)",
                   sent.get("output_config", {}).get("format", {}).get("type")
                   == "json_schema")
            _check("adaptive thinking + pinned model",
                   sent.get("thinking", {}).get("type") == "adaptive"
                   and sent.get("model"))
            _check("facts are compact (no raw event dump)",
                   "raw_category" not in body and len(body) < 4000)
            _check("explain-only system prompt (not a detector)",
                   "not a detector" in sent.get("system", ""))

            print("\n[4] Unshipped action rejected despite valid shape")
            _FakeClient.reply = dict(_FakeClient.reply,
                                     recommended_action={"action": "wipe_disk",
                                                         "target": "C:",
                                                         "rationale": "no"})
            rep4 = investigator.investigate(inc, use_ai=True)
            _check("dangerous action rejected -> fallback to offline",
                   rep4["analyst"] == "offline" and "ai_error" in rep4)

            print("\n[5] Network failure -> honest fallback")
            _FakeClient.raise_on_call = True
            rep5 = investigator.investigate(inc, use_ai=True)
            _check("ai_error on failure, offline analysis intact",
                   "failed" in rep5.get("ai_error", "") and rep5["summary"])
        finally:
            inv._ai_available = real_import
            sys.modules.pop("anthropic", None)

        engine.stop()
        store.stop()

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
