#!/usr/bin/env python3
"""Validation suite for the killchain confidence-model fix.

Context: an investigation (read-only, against the real code) found that
KillChainCorrelator.observe() treated "3 distinct ATT&CK tactics on one
actor" as worth automatic high confidence, with no regard for how strong the
underlying evidence was, whether the process lineage was actually verified,
or how tightly the stages were clustered in time. A real, code-verified
benign developer sequence (IDE terminal -> encoded PowerShell startup ->
MSBuild build step -> hostname.exe for a build log) crossed the 3-tactic bar
on a fully PID-verified lineage and scored "high" (0.75) - the same verdict
as a genuine credential-theft chain - purely because tactic-diversity alone
was being read as evidence of coordinated attack behavior.

The fix (killchain.py's score_chain/observe, engine.py's _correlate_chain,
investigate.py's _assess_confidence) makes the score a function of THREE
additional, honestly-named quality factors - evidence strength, lineage
verification, temporal clustering - and makes investigate.py's human-facing
confidence tier a direct, honest read of that same graded score (never more
certain than the evidence-generating layer). This file is the demanded
validation: the exact benign workflow from the investigation, replayed
against the real code, plus the explicit variations requested before this
milestone could be called done.

  [1] Exact benign replay: PowerShell -> MSBuild -> hostname, PID-verified,
      tight timing - must NOT reach "high" anymore.
  [2] Same workflow with longer timing gaps - confidence should not improve
      just because the developer took longer.
  [3] Multiple independent PowerShell processes (different PIDs, no shared
      lineage) - must NOT bundle into one high-confidence chain via name.
  [4] Unrelated processes sharing the same parent (e.g. many short-lived
      terminal children of one long-lived IDE) - each stays its own chain
      (killchain's own union-find), and the INCIDENT layer must not
      re-merge them via a shared display name (the real "25 unrelated
      lineages in one incident" bug).
  [5] PID-present (verified) lineage scores at least as high as the same
      shape with PID-missing (name-fallback) lineage.
  [6] PID-missing/name-fallback lineage: same tactics, weaker link - still
      correlates (real corroboration), never zeroed out.
  [7] A genuinely malicious multi-stage chain (high/critical severity,
      verified lineage, tight timing, reaches a high-impact tactic) must
      still land at "high" confidence - the fix must not blunt real
      detection.
  [8] End-to-end through investigate.py: the benign chain's HUMAN-FACING
      confidence tier is provably no more certain than the graded score
      that produced it ("never let the confidence layer outrun the
      evidence").

No network, no Windows APIs. Exit 0 on success, non-zero on failure
(standalone-script contract, matching tests/run_safe.py's test_*.py glob).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.killchain import KillChainCorrelator
from valkyrie.edr.investigate import Investigator, _assess_confidence
from valkyrie.edr.schema import Detection, Incident

_FAILS: list = []


def _check(cond: bool, msg: str) -> None:
    print(("  [+] " if cond else "  [!] FAIL ") + msg)
    if not cond:
        _FAILS.append(msg)


class _FakeStore:
    def __init__(self, detections: list) -> None:
        self._detections = detections

    def list_detections(self, incident_id: str = "", limit: int = 200) -> list:
        return self._detections


def main() -> int:
    print("Killchain confidence-model validation")
    print("=" * 60)

    # -- 1: exact benign replay from the investigation ----------------------
    print("\n-- 1: PowerShell -> MSBuild -> hostname, PID-verified, tight timing --")
    kc = KillChainCorrelator(window_seconds=600.0)
    kc.observe("powershell.exe", "T1059.001", "IDE launches PowerShell "
               "(-EncodedCommand shell-integration startup)", 0.0,
               pid=5000, severity="low")     # real: execpolicy-bypass/encoded-command rules are SEV_LOW
    kc.observe("powershell.exe", "T1027", "startup blob flagged obfuscated",
               0.5, pid=5000, severity="medium")   # real: generic obfuscated-command fallback is SEV_MEDIUM
    kc.observe("MSBuild.exe", "T1127.001", "normal project build",
               20.0, pid=5101, ppid=5000, severity="low")
    result = kc.observe("hostname.exe", "T1082", "build script prints "
                        "environment info for the log header",
                        45.0, pid=5102, ppid=5000, severity="info")  # real: discovery labels are ALWAYS SEV_INFO
    _check(result is not None, "3 distinct tactics still correlates (this is real, structural evidence)")
    _check(result["distinct_tactics"] == 3, "sanity: 3 distinct tactics counted")
    _check(result["severity"] != "high" and result["severity"] != "critical",
           f"the benign chain no longer reaches high/critical severity (got {result['severity']!r})")
    _check(result["score"] < 0.7,
           f"the benign chain's score is below the old 'high' floor of 0.7 (got {result['score']})")
    _check(result["quality"]["evidence"] <= 0.7,
           f"evidence_quality correctly reflects that nothing here is stronger than medium severity (got {result['quality']})")
    print(f"      score={result['score']} severity={result['severity']} quality={result['quality']}")
    print(f"      explanation: {result['explanation']}")

    # -- 2: same workflow, longer timing gaps --------------------------------
    print("\n-- 2: same shape, spread across most of the 600s window --")
    kc2 = KillChainCorrelator(window_seconds=600.0)
    kc2.observe("powershell.exe", "T1059.001", "startup", 0.0, pid=6000, severity="low")
    kc2.observe("powershell.exe", "T1027", "obfuscated", 1.0, pid=6000, severity="medium")
    kc2.observe("MSBuild.exe", "T1127.001", "build", 300.0, pid=6101, ppid=6000, severity="low")
    result_spread = kc2.observe("hostname.exe", "T1082", "log header",
                                580.0, pid=6102, ppid=6000, severity="info")
    _check(result_spread is not None, "still correlates when spread out")
    _check(result_spread["quality"]["temporal"] < result["quality"]["temporal"],
           f"spreading the SAME shape across the window lowers temporal_quality "
           f"(tight={result['quality']['temporal']}, spread={result_spread['quality']['temporal']})")
    _check(result_spread["score"] <= result["score"],
           "confidence does not improve just because the developer took longer "
           "(coordination claim gets WEAKER, not stronger, as events spread out)")

    # -- 3: multiple independent PowerShell processes, no shared lineage ----
    print("\n-- 3: two independent powershell.exe processes (different PIDs, no ppid edge) --")
    kc3 = KillChainCorrelator(window_seconds=600.0, min_tactics=3)
    kc3.observe("powershell.exe", "T1059.001", "session A: exec", 0.0, pid=7001, severity="high")
    kc3.observe("powershell.exe", "T1027", "session A: obfuscated", 1.0, pid=7001, severity="high")
    r_a_alone = kc3.observe("powershell.exe", "T1082", "session A: discovery",
                            2.0, pid=7001, severity="info")
    # A second, causally-unrelated powershell.exe (different real PID) doing
    # its own single-tactic thing must NOT borrow session A's tactic count.
    r_b = kc3.observe("powershell.exe", "T1005", "session B: unrelated collection",
                      3.0, pid=7002, severity="medium")
    _check(r_a_alone is not None, "session A alone (3 real tactics, high+high+info) correlates on its own merits")
    _check(r_b is None, "an unrelated PID with only 1 tactic does NOT inherit session A's chain")

    # -- 4: unrelated processes sharing the same long-lived parent -----------
    print("\n-- 4: many unrelated short-lived children of one long-lived parent (e.g. an IDE) --")
    kc4 = KillChainCorrelator(window_seconds=600.0, min_tactics=3)
    chain_ids = set()
    for i in range(6):
        base_pid = 8000 + i * 10
        kc4.observe("child.exe", "T1059.001", f"session {i}: exec", float(i * 60),
                   pid=base_pid, ppid=1, severity="low")   # ppid=1: the shared long-lived IDE, never itself chained on
        kc4.observe("child.exe", "T1027", f"session {i}: obfuscated", float(i * 60 + 1),
                   pid=base_pid, ppid=1, severity="medium")
        r = kc4.observe("tool.exe", "T1082", f"session {i}: discovery", float(i * 60 + 2),
                        pid=base_pid + 1, ppid=base_pid, severity="info")
        if r:
            chain_ids.add(r["chain_id"])
    _check(len(chain_ids) > 1,
           f"6 genuinely independent sessions sharing one never-itself-flagged parent do "
           f"NOT all collapse into a single mega-chain (a real gap this validation suite "
           f"found: an inert, high-fan-out ancestor like a long-lived IDE was enough to "
           f"merge unlimited unrelated sessions via the ppid edge alone; got "
           f"{len(chain_ids)} distinct chain_id(s), fixed via a fan-out cap on parent "
           f"tokens that were never themselves directly observed)")

    # engine-level: verify the INCIDENT layer doesn't re-merge them by name.
    print("      (engine-level: distinct chain_ids get distinct incident correlation keys)")
    import tempfile, time as _time
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "bundle.db"); store.start()
        engine = EdrEngine(store); engine.start()
        for i in range(4):
            base_pid = 9000 + i * 10
            engine.report_detection(Detection(source="s", severity="low", category="process",
                title=f"s{i} exec", process_name="child.exe", process_pid=base_pid,
                technique="T1059.001"))
            engine.report_detection(Detection(source="s", severity="medium", category="process",
                title=f"s{i} obf", process_name="child.exe", process_pid=base_pid,
                technique="T1027"))
            engine.report_detection(Detection(source="s", severity="info", category="process",
                title=f"s{i} disc", process_name="tool.exe", process_pid=base_pid + 1,
                technique="T1082", details={"ppid": base_pid}))
        _time.sleep(0.3)
        chains = [inc for inc in engine.list_incidents() if inc["category"] == "attack_chain"]
        _check(len(chains) == 4,
               f"4 independent lineages raise 4 SEPARATE attack_chain incidents, not 1 "
               f"bundled incident (this is the real bug: entity used to be the shared "
               f"origin display name; got {len(chains)} incident(s))")
        engine.stop(); store.stop()

    # -- 5 & 6: PID-present vs PID-missing lineage ---------------------------
    print("\n-- 5/6: verified (PID) lineage vs name-fallback lineage, same tactics/severity/timing --")
    kc5 = KillChainCorrelator(window_seconds=600.0, min_tactics=3)
    kc5.observe("evil.exe", "T1059.001", "exec", 0.0, pid=1111, severity="high")
    kc5.observe("evil.exe", "T1027", "obfuscated", 1.0, pid=1111, severity="high")
    verified = kc5.observe("evil.exe", "T1082", "discovery", 2.0, pid=1111, severity="high")

    kc6 = KillChainCorrelator(window_seconds=600.0, min_tactics=3)
    kc6.observe("evil.exe", "T1059.001", "exec", 0.0, severity="high")           # no pid
    kc6.observe("evil.exe", "T1027", "obfuscated", 1.0, severity="high")        # no pid
    fallback = kc6.observe("evil.exe", "T1082", "discovery", 2.0, severity="high")  # no pid

    _check(verified is not None and fallback is not None, "both variants correlate")
    _check(verified["quality"]["lineage"] > fallback["quality"]["lineage"],
           f"PID-verified lineage scores strictly higher than name-fallback "
           f"(verified={verified['quality']['lineage']}, fallback={fallback['quality']['lineage']})")
    _check(verified["score"] >= fallback["score"],
           f"verified lineage never scores LOWER than the equivalent name-fallback chain "
           f"(verified={verified['score']}, fallback={fallback['score']})")
    _check(fallback["score"] > 0.0,
           "name-fallback lineage is still real corroboration - never zeroed out")
    _check(fallback["score"] >= 0.35,
           f"a strong (all-high-severity), tightly-timed, name-linked chain still lands "
           f"well above the 'insufficient' floor even without PID verification - lineage "
           f"is ONE factor that lowers the tier, not a veto that erases the evidence "
           f"(got score={fallback['score']})")

    # -- 7: a genuinely malicious multi-stage chain must still read HIGH -----
    print("\n-- 7: genuine attack - verified lineage, high/critical severity, tight timing, reaches an objective --")
    kc7 = KillChainCorrelator(window_seconds=600.0, min_tactics=3)
    kc7.observe("powershell.exe", "T1059.001", "IEX download cradle", 0.0,
               pid=4242, severity="high")
    kc7.observe("rundll32.exe", "T1055", "process injection", 1.0,
               pid=4243, ppid=4242, severity="high")
    malicious = kc7.observe("rundll32.exe", "T1003.001", "LSASS memory access",
                            2.0, pid=4243, severity="critical")
    _check(malicious is not None, "genuine 3-tactic attack correlates")
    _check(malicious["severity"] == "critical",
           f"a genuine, well-evidenced, tightly-timed, verified-lineage attack reaching "
           f"credential-access still reaches CRITICAL severity (got {malicious['severity']!r}) "
           f"- the fix does not blunt real detection")
    _check(malicious["score"] >= 0.9, f"score reflects that (got {malicious['score']})")
    _check(malicious["reaches_objective"] is True, "correctly flags the high-impact objective")

    # -- 8: end-to-end through investigate.py - confidence never outruns evidence
    print("\n-- 8: investigate.py's human-facing tier is a direct, honest read of the same score --")
    chain_det_benign = Detection(
        source="edr.killchain", severity=result["severity"], category="attack_chain",
        title="Multi-stage attack on powershell.exe: 3 ATT&CK tactics across 3 linked processes",
        entity=f"chain:{result['chain_id']}", process_name="", process_pid=5102,
        technique="; ".join(result["techniques"]),
        details={"chain": result, "reason": result["explanation"], "confidence": result["score"]},
    )
    inc_benign = Incident(title=chain_det_benign.title, severity=result["severity"], category="attack_chain")
    tier, reasons = _assess_confidence(inc_benign, [chain_det_benign], ["attack_chain"], {"available": False})
    _check(tier != "high",
           f"the benign replay's HUMAN-FACING confidence tier is not 'high' (got {tier!r}) - "
           f"matches the graded score, not the bare category label")
    _check(tier in ("medium", "low", "insufficient"),
           f"tier is a real, named grade, not a silent pass-through (got {tier!r})")
    print(f"      confidence={tier!r} reasons={reasons}")

    chain_det_malicious = Detection(
        source="edr.killchain", severity=malicious["severity"], category="attack_chain",
        title="Multi-stage attack on powershell.exe: 3 ATT&CK tactics across 2 linked processes",
        entity=f"chain:{malicious['chain_id']}", process_name="", process_pid=4243,
        technique="; ".join(malicious["techniques"]),
        details={"chain": malicious, "reason": malicious["explanation"], "confidence": malicious["score"]},
    )
    inc_mal = Incident(title=chain_det_malicious.title, severity=malicious["severity"], category="attack_chain")
    tier_mal, reasons_mal = _assess_confidence(inc_mal, [chain_det_malicious], ["attack_chain"], {"available": False})
    _check(tier_mal == "high",
           f"the genuine attack's human-facing tier IS 'high' (got {tier_mal!r}) - "
           f"real multi-stage attacks are still flagged assertively")

    # Full report end-to-end, through the real Investigator, on the benign replay.
    rep = Investigator(edr_store=_FakeStore([chain_det_benign])).investigate(inc_benign, use_ai=False)
    dec = rep["decision"]
    _check(dec["confidence"] != "high",
           f"full report end-to-end: benign replay's decision.confidence is not 'high' (got {dec['confidence']!r})")
    action_text = (dec["recommended_action_plain"] or "").lower()
    _check("disconnect this device from the network" not in action_text
           or "if you don't recognize" in action_text or "worth a closer look" in action_text,
           f"the benign replay's recommended action is hedged, not an unconditional "
           f"'disconnect now' (got: {action_text!r})")

    print("\n" + "=" * 60)
    if _FAILS:
        print(f"  RESULT: {len(_FAILS)} FAILURE(S)")
        return 1
    print("  RESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
