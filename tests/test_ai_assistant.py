#!/usr/bin/env python3
"""AI assistant seam — offline tests with a fake, vendor-neutral provider.

The philosophy under test: AI explains, it never detects. The offline
heuristic analyst must always produce a complete report; LLM output is
additive, structured, evidence-grounded, and every failure mode falls back
cleanly. The backend is abstracted behind ``ai_provider.AIProvider`` — this
test injects a fake provider, so it is vendor-neutral (no SDK, no network).

  [1] Offline analyst always works (no provider, no network)
  [2] use_ai without a provider -> ai_error + offline analysis intact
  [3] Structured analysis via a fake provider; the facts sent are compact
      (no raw event dump) and the prompt is explain-only
  [4] Guard: schema-conforming reply with an unshipped action is rejected
  [5] Provider failure (returns None) -> ai_error fallback, report intact
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


class _FakeProvider:
    """A stand-in AIProvider that records the prompts it received."""
    name = "testllm"
    last_system = ""
    last_user = ""
    last_schema: dict = {}
    reply = None            # dict -> returned; None -> simulates a failure

    def available(self) -> bool:
        return True

    def analyze(self, system, user, schema):
        _FakeProvider.last_system = system
        _FakeProvider.last_user = user
        _FakeProvider.last_schema = schema
        return _FakeProvider.reply


def main() -> int:
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.edr.schema import Detection
    import valkyrie.edr.investigate as inv

    print("\n=== AI assistant seam (explain-only, vendor-neutral) ===\n")

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
        investigator = inv.Investigator(engine._edr)
        real_get_provider = inv.get_provider

        print("[1] Offline analyst always works")
        rep = investigator.investigate(inc)
        _check("report produced with analyst=offline",
               rep["analyst"] == "offline" and rep["summary"])
        _check("recommended actions from shipped set",
               all(a["action"] in ("block_domain", "kill_process",
                                   "isolate_host")
                   for a in rep["recommended_actions"]))
        _check("MITRE technique surfaced", "T1071" in rep["techniques"])

        print("\n[2] use_ai without a provider -> honest error + fallback")
        saved = {k: os.environ.pop(k, None) for k in
                 ("ANTHROPIC_API_KEY", "VALKYRIE_AI_KEY", "OPENAI_API_KEY",
                  "VALKYRIE_AI_PROVIDER", "VALKYRIE_AI_BASE_URL")}
        try:
            rep2 = investigator.investigate(inc, use_ai=True)   # real -> offline provider
            _check("ai_error explains missing provider",
                   "no provider" in rep2.get("ai_error", ""))
            _check("offline analysis still present", rep2["summary"])
            _check("analyst stays offline", rep2["analyst"] == "offline")
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

        print("\n[3] Structured analysis via a fake provider")
        inv.get_provider = lambda: _FakeProvider()
        try:
            _FakeProvider.reply = {
                "assessment": "mal.exe beaconed to evil.example, a known "
                              "threat-intel indicator.",
                "confidence": "high",
                "likely_technique": "T1071",
                "recommended_action": {"action": "kill_process",
                                       "target": "mal.exe",
                                       "rationale": "stop the beacon"},
                "evidence": ["connection to threat-intel IP"],
            }
            rep3 = investigator.investigate(inc, use_ai=True)
            _check("analyst=<provider name> with structured analysis",
                   rep3["analyst"] == "testllm"
                   and rep3["ai_analysis"]["confidence"] == "high")
            _check("narrative mirrors assessment",
                   rep3["ai_narrative"].startswith("mal.exe beaconed"))
            _check("schema passed to provider (structured output)",
                   _FakeProvider.last_schema.get("required")
                   and "recommended_action" in _FakeProvider.last_schema["required"])
            _check("facts are compact (no raw event dump)",
                   "raw_category" not in _FakeProvider.last_user
                   and len(_FakeProvider.last_user) < 6000)
            _check("explain-only system prompt (not a detector)",
                   "not a detector" in _FakeProvider.last_system)

            print("\n[4] Unshipped action rejected despite valid shape")
            _FakeProvider.reply = dict(_FakeProvider.reply,
                                       recommended_action={"action": "wipe_disk",
                                                           "target": "C:",
                                                           "rationale": "no"})
            rep4 = investigator.investigate(inc, use_ai=True)
            _check("dangerous action rejected -> fallback to offline",
                   rep4["analyst"] == "offline" and "ai_error" in rep4)

            print("\n[5] Provider failure -> honest fallback")
            _FakeProvider.reply = None
            rep5 = investigator.investigate(inc, use_ai=True)
            _check("ai_error on failure, offline analysis intact",
                   "failed" in rep5.get("ai_error", "") and rep5["summary"])
        finally:
            inv.get_provider = real_get_provider

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
