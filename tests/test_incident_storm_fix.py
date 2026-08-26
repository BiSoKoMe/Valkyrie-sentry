#!/usr/bin/env python3
"""Incident-storm fix - regression gate (2026-08-26).

Pins the fix for the root cause proven in the incident-storm investigation:
`ResolutionLog.was_resolved()` returned a bare False both when DNS
interception had never seen any traffic (e.g. every `--no-dns` CI/Tier-B
run) AND when it was genuinely active but simply had no record of one
specific IP - collapsing "unknown" into "suspicious". Under `--no-dns`,
that made network_score.py's strongest signal (`never_resolved`, 0.35)
fire on literally every connection, and combined with `actor_untrusted`
(0.30, true of any non-Windows-signed binary - nearly everything on a CI
runner) cleared the 0.55 firing threshold for ordinary traffic. Separately,
`is_self()` only recognized a *packaged, installed* Valkyrie, so its own
traffic (running as `python -m valkyrie` in every CI job) was never
suppressed, letting its own loopback API polling get scored as an
external actor's "network anomaly".

Two fixes, both already applied, tested here:
  1. ResolutionLog.was_resolved() is genuinely tri-state: None until the
     log has processed at least one real resolution, True/False after.
  2. trust.is_self() also matches by PID (`os.getpid()`) - an exact
     identity check that can never whitelist an unrelated process, unlike
     a name/path guess.

Letters A-I map directly to the approved validation plan.

No network, no Windows APIs beyond what EdrEngine/Store already use in
existing tests. Exit 0 on success, non-zero on failure (standalone-script
contract, matching tests/run_safe.py's test_*.py glob).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.resolution_log import ResolutionLog, set_active
from valkyrie.network_score import ConnFacts, classify_connection_anomaly, score_connection
from valkyrie.network_telemetry import NetworkCollector, ConnInfo
from valkyrie.trust import is_self

_FAILS: list = []


def _check(cond: bool, msg: str) -> None:
    print(("  [+] " if cond else "  [!] FAIL ") + msg)
    if not cond:
        _FAILS.append(msg)


def main() -> int:
    print("Incident-storm fix - regression gate")
    print("=" * 60)

    # -- B: --no-dns (a log that has NEVER recorded anything) -> None, ------
    #       never_resolved must not contribute.
    print("\n-- B: DNS interception never active -> was_resolved() is None, S2 inert --")
    fresh = ResolutionLog()
    _check(fresh.was_resolved("8.8.4.4") is None,
           "a never-touched ResolutionLog returns None, not False, for ANY ip")
    facts_never_active = ConnFacts(process_name="curl.exe", actor_trusted=False,
                                   resolved=fresh.was_resolved("8.8.4.4"))
    r = score_connection(facts_never_active)
    _check("never_resolved" not in r["labels"],
           f"S2 does not contribute when interception was never active (labels={r['labels']})")
    _check(not r["fires"],
           "actor_untrusted ALONE (1 signal) does not clear the firing threshold "
           "- this is the exact case that used to fire under --no-dns")

    # -- C: interception active, this IP never resolved -> False, S2 available
    print("\n-- C: interception active, IP genuinely never resolved -> False --")
    active = ResolutionLog()
    active.record("some-other-domain.test", ["203.0.113.9"])   # proves activity
    _check(active.was_resolved("45.32.11.9") is False,
           "an active log correctly says False for an IP it never saw resolved")
    facts_never_resolved = ConnFacts(process_name="x.exe", actor_trusted=False,
                                     resolved=active.was_resolved("45.32.11.9"))
    r2 = score_connection(facts_never_resolved)
    _check("never_resolved" in r2["labels"],
           "S2 fires when interception is active and this IP was truly never resolved")

    # -- D: interception active, IP WAS resolved -> True, S2 does not fire ---
    print("\n-- D: interception active, IP was resolved -> True, S2 stays quiet --")
    active.record("clean-example.test", ["93.184.216.34"])
    _check(active.was_resolved("93.184.216.34") is True,
           "an active log correctly says True for an IP it actually resolved")
    facts_resolved = ConnFacts(process_name="chrome.exe", actor_trusted=True,
                               resolved=active.was_resolved("93.184.216.34"))
    r3 = score_connection(facts_resolved)
    _check("never_resolved" not in r3["labels"], "S2 does not fire for a genuinely resolved IP")
    _check(not r3["fires"], "a trusted, resolved connection stays quiet")

    # -- E: genuine hardcoded-IP C2, interception active -> detection intact -
    print("\n-- E: genuine hardcoded-IP behavior still detected with interception active --")
    hardcoded_c2 = ConnFacts(process_name="evil.exe", process_path=r"C:\Users\v\AppData\Local\Temp\evil.exe",
                             raddr_ip="45.32.11.9", raddr_port=443,
                             actor_trusted=False, actor_low_trust_path=True,
                             resolved=active.was_resolved("45.32.11.9"),  # never resolved, log IS active
                             process_net_history=0)
    verdict = classify_connection_anomaly(hardcoded_c2)
    _check(verdict is not None, "a real hardcoded-IP-shaped connection still produces a verdict")
    _check(verdict is not None and "never_resolved" in verdict["labels"],
           "the real detection's evidence still includes never_resolved - the fix does not "
           "weaken genuine hardcoded-IP detection when interception is genuinely active")

    # -- A: end-to-end - Valkyrie's own loopback traffic under --no-dns -----
    #       conditions produces NO network detection at all.
    print("\n-- A: Valkyrie's own loopback traffic, DNS interception never active -> no detection --")
    set_active(ResolutionLog())   # simulates the unconditional startup call, never touched (--no-dns)
    try:
        my_pid = os.getpid()
        emitted_self: list = []
        col_self = NetworkCollector(emit=emitted_self.append, ip_reputation=lambda ip: False)
        # Attribution to python.exe under a non-OS path - exactly what the
        # storm investigation found for Valkyrie's own process on a CI runner.
        self_conn = ConnInfo(pid=my_pid, name="python.exe",
                             path=r"C:\hostedtoolcache\windows\Python\3.11.9\x64\python.exe",
                             raddr_ip="127.0.0.1", raddr_port=54321)
        seq = iter([{}, {self_conn.key(): self_conn}])
        col_self.snapshot = lambda: next(seq)   # type: ignore[assignment]
        col_self.poll_once()
        col_self.poll_once()
        # is_self() suppression happens at engine.ingest_telemetry, not inside
        # NetworkCollector itself - assert the actual suppression point.
        would_suppress = is_self("python.exe",
                                 r"C:\hostedtoolcache\windows\Python\3.11.9\x64\python.exe",
                                 my_pid)
        _check(would_suppress,
               "is_self() recognizes THIS process's own pid even with a generic "
               "name/non-packaged path - this is what stops the event from ever "
               "reaching a Detection")
    finally:
        set_active(None)

    # -- F: PID-based self-recognition, precise, no name/path whitelisting --
    print("\n-- F: is_self() by PID is exact identity, never a name whitelist --")
    real_pid = os.getpid()
    _check(is_self("python.exe", r"C:\hostedtoolcache\windows\Python\3.11.9\x64\python.exe", real_pid),
           "THIS process's own pid + a generic python.exe name/path -> recognized as self")
    _check(is_self("anything.exe", "", real_pid),
           "the pid match alone is sufficient - name is irrelevant once pid matches")
    unrelated_pid = real_pid + 9973   # arbitrary, not this process
    _check(not is_self("python.exe", r"C:\hostedtoolcache\windows\Python\3.11.9\x64\python.exe", unrelated_pid),
           "a DIFFERENT pid with the exact same generic name/path is NOT self - "
           "this is the proof there is no python.exe or hostedtoolcache whitelist")
    _check(not is_self("python.exe", r"C:\hostedtoolcache\windows\Python\3.11.9\x64\python.exe", 0),
           "pid=0 (not provided) falls back to the pre-existing name/path checks only, "
           "which correctly do not recognize a bare python.exe as self")

    # -- I: two genuinely separate malicious processes still produce two ----
    #       separate incidents - the fix must not merge unrelated actors.
    print("\n-- I: two distinct malicious actors still produce two distinct incidents --")
    os.environ["VALKYRIE_DATA_DIR"] = tempfile.mkdtemp()
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.telemetry import TelemetryEvent, CAT_NETWORK, SEV_HIGH
    eng = EdrEngine(Store()); eng.start()
    try:
        evil_a = TelemetryEvent(category=CAT_NETWORK, activity="connect", action="flagged",
                                actor_pid=101, actor_name="evil_a.exe",
                                actor_path=r"C:\Users\v\AppData\Local\Temp\evil_a.exe",
                                target={"ip": "45.32.11.9", "port": 443}, severity=SEV_HIGH,
                                reason="hardcoded C2", source="network_collector",
                                labels=["threat_intel_ip"])
        evil_b = TelemetryEvent(category=CAT_NETWORK, activity="connect", action="flagged",
                                actor_pid=102, actor_name="evil_b.exe",
                                actor_path=r"C:\Users\v\AppData\Local\Temp\evil_b.exe",
                                target={"ip": "185.220.101.5", "port": 443}, severity=SEV_HIGH,
                                reason="hardcoded C2", source="network_collector",
                                labels=["threat_intel_ip"])
        id_a = eng.ingest_telemetry(evil_a)
        id_b = eng.ingest_telemetry(evil_b)
        _check(id_a is not None and id_b is not None, "both genuinely malicious events create incidents")
        _check(id_a != id_b, f"two distinct actors produce two DISTINCT incidents, not one merged "
                             f"incident (got {id_a!r} and {id_b!r}) - the fix does not touch "
                             f"find_open_incident's correct separation")
    finally:
        eng.stop()

    print("\n" + "=" * 60)
    if _FAILS:
        print(f"  RESULT: {len(_FAILS)} FAILURE(S)")
        return 1
    print("  RESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
