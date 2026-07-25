#!/usr/bin/env python3
"""Multi-stage kill-chain correlation tests.

Pins the fix for the measured correlation gap: the base correlator groups
detections by SAME category, so one intrusion (execution → C2 → persistence
on the same process) fragmented into several individually-unremarkable
incidents. The kill-chain correlator scores the *sequence* and raises one
escalating incident.

  [1] Pure mapping + scoring: technique→tactic, score rises with distinct
      tactics, high-impact bump, severity thresholds
  [2] Correlator: emits only on >=2 distinct tactics, only on GROWTH (no
      alert storm), window eviction, unattributable/unmapped inputs ignored
  [3] Engine end-to-end: three same-process detections across three tactics
      raise ONE 'attack_chain' incident; benign single-tactic activity does
      not; the chain explains itself and maps to MITRE
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.edr.killchain import (
        KillChainCorrelator, tactic_for, extract_technique_id, score_chain,
        HIGH_IMPACT_TACTICS,
    )

    print("\n=== kill-chain correlation ===\n")

    print("[1] Technique → tactic + scoring (pure)")
    _check("PowerShell → execution", tactic_for("T1059.001 — PowerShell") == "execution")
    _check("DNS C2 → command-and-control", tactic_for("T1071.004") == "command-and-control")
    _check("Run key → persistence", tactic_for("T1547.001") == "persistence")
    _check("LSASS → credential-access", tactic_for("T1003.001") == "credential-access")
    _check("ransomware → impact", tactic_for("T1486") == "impact")
    _check("sub-technique falls back to base",
           tactic_for("T1055.999 — unknown sub") == "defense-evasion")
    _check("unmapped technique → None", tactic_for("T9999") is None)
    _check("no id in text → None", tactic_for("just words") is None)
    _check("extract id from label", extract_technique_id("T1003.001 — LSASS") == "T1003.001")

    s2, sev2 = score_chain({"execution", "command-and-control"})
    s3, sev3 = score_chain({"execution", "command-and-control", "persistence"})
    s4, _ = score_chain({"execution", "command-and-control", "persistence", "impact"})
    _check("2 tactics scores below 3", s2 < s3)
    _check("3 tactics scores below 4", s3 < s4)
    _check("high-impact tactic raises the score",
           score_chain({"execution", "impact"})[0] > 0.25 * 2)
    _check("4-tactic chain reaching impact is critical", sev4_is_crit := (score_chain(
        {"execution", "command-and-control", "persistence", "impact"})[1] == "critical"))
    _check("2 benign-ish tactics is at most high", sev2 in ("medium", "high"))

    print("\n[2] Correlator (deterministic ts)")
    kc = KillChainCorrelator(window_seconds=600, min_tactics=2)
    now = 1000.0
    _check("single tactic → no chain",
           kc.observe("powershell.exe", "T1059.001", "encoded cmd", now) is None)
    c = kc.observe("powershell.exe", "T1071.004", "DNS beacon", now + 5)
    _check("second distinct tactic → chain emitted", c is not None)
    _check("chain names the actor", c and c["actor"] == "powershell.exe")
    _check("chain lists 2 distinct tactics", c and c["distinct_tactics"] == 2)
    _check("chain explains itself", c and "independent ATT&CK tactics" in c["explanation"])
    # Same tactic again → no NEW tactic → stays quiet (no alert storm)
    _check("repeat tactic does not re-alert",
           kc.observe("powershell.exe", "T1071.004", "DNS beacon 2", now + 6) is None)
    # Third distinct tactic → grows → re-emits, higher score
    c3 = kc.observe("powershell.exe", "T1547.001", "run key", now + 7)
    _check("new tactic re-emits with growth", c3 is not None and c3["distinct_tactics"] == 3)
    _check("score grew with the third stage", c3 and c3["score"] > c["score"])
    # Different actor is independent
    _check("unrelated actor not folded in",
           kc.observe("chrome.exe", "T1059.001", "x", now + 8) is None)
    # Unattributable / unmapped ignored
    _check("no actor → ignored", kc.observe("", "T1059.001", "x", now + 9) is None)
    _check("unmapped technique → ignored",
           kc.observe("evil.exe", "T9999", "x", now + 9) is None)
    # Window eviction: a tactic older than the window drops out
    kc2 = KillChainCorrelator(window_seconds=100, min_tactics=2)
    kc2.observe("mal.exe", "T1059.001", "exec", 0.0)
    _check("stale first tactic evicted → second alone is no chain",
           kc2.observe("mal.exe", "T1071.004", "c2", 500.0) is None)

    print("\n[3] Engine end-to-end")
    import tempfile
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.edr.schema import Detection
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "kc.db"); store.start()
        engine = EdrEngine(store); engine.start()

        # Same process, three ATT&CK tactics, in-window.
        engine.report_detection(Detection(source="etw.ps", severity="medium",
            category="process", title="encoded PowerShell", entity="C:/x",
            process_name="powershell.exe", technique="T1059.001 — PowerShell"))
        engine.report_detection(Detection(source="dns.beacon", severity="high",
            category="intelligence", title="C2 beacon", entity="evil-c2.example",
            process_name="powershell.exe", technique="T1071.004 — DNS C2"))
        engine.report_detection(Detection(source="etw.persist", severity="high",
            category="persistence", title="Run key", entity="HKCU\\...\\Run",
            process_name="powershell.exe", technique="T1547.001 — Run key"))
        time.sleep(0.2)

        incidents = engine.list_incidents()
        chains = [i for i in incidents if i["category"] == "attack_chain"]
        _check("a single attack_chain incident was raised", len(chains) == 1)
        if chains:
            ch = engine.get_incident(chains[0]["id"])
            _check("chain incident is high or critical",
                   ch["severity"] in ("high", "critical"))
            det0 = (ch.get("detections") or [{}])[0]
            reason = (det0.get("details") or {}).get("reason", "")
            _check("chain incident explains itself", "ATT&CK tactics" in reason)
            _check("chain carries multiple techniques",
                   ";" in (det0.get("technique") or ""))

        # A different process doing ONE thing must NOT create a chain.
        engine.report_detection(Detection(source="dns", severity="low",
            category="tracker", title="ad", entity="doubleclick.net",
            process_name="chrome.exe", technique="T1041"))
        time.sleep(0.15)
        chains2 = [i for i in engine.list_incidents() if i["category"] == "attack_chain"]
        _check("single-tactic benign actor raised no chain", len(chains2) == 1)

        # Explainability coverage for the new categories.
        from valkyrie.edr.investigate import KNOWN_INCIDENT_CATEGORIES, _MEANING, _RECOMMEND
        for cat in ("attack_chain", "tunnel", "dyndns"):
            _check(f"'{cat}' has meaning + recommendation",
                   cat in KNOWN_INCIDENT_CATEGORIES and cat in _MEANING and cat in _RECOMMEND)

        engine.stop(); store.stop()

    print("\n" + "=" * 50)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
