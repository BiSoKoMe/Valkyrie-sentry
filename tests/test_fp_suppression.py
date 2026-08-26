#!/usr/bin/env python3
"""False-positive suppression tests (valkyrie/trust.py + engine self-exclusion).

These pin the FP classes a live Atomic Red Team run exposed, so they cannot
regress: Valkyrie flagging ITSELF, public DNS resolvers scored as C2, and the
constant legit Windows autorun churn (services.exe/sihost/TrustedInstaller).
Each fix must NOT weaken a real detection - the negative controls check that.

  [1] is_self recognises Valkyrie's own binaries/processes, not third parties
  [2] public DNS resolvers are never threat IPs; a real bad IP still is
  [3] benign OS autorun (trusted writer, non-scratch target) is trusted;
      a trusted process dropping an autorun into %TEMP% still flags
  [4] engine self-exclusion suppresses Valkyrie's own telemetry, not a threat's
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.trust import is_self, is_public_resolver_ip, is_benign_os_autorun

_failures = 0


def _check(label: str, ok: bool) -> None:
    global _failures
    if not ok:
        _failures += 1
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}")


def test_is_self() -> None:
    print("[1] is_self")
    _check("valkyrie.exe by name", is_self("valkyrie.exe", ""))
    _check("nssm.exe by name", is_self("nssm.exe", ""))
    _check("engine by path", is_self("", r"C:\Program Files\Valkyrie\resources\engine\valkyrie.exe"))
    _check("programdata by path", is_self("", r"C:\ProgramData\Valkyrie\valkyrie.db"))
    _check("chrome is NOT self", not is_self("chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe"))
    _check("empty is NOT self", not is_self("", ""))


def test_public_resolvers() -> None:
    print("[2] public resolver allowlist")
    for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"):
        _check(f"{ip} is a public resolver", is_public_resolver_ip(ip))
    _check("a real C2 IP is NOT allowlisted", not is_public_resolver_ip("45.9.148.1"))
    # The allowlist must actually short-circuit the threat-intel IP path even
    # when the feed wrongly contains a resolver IP.
    from valkyrie.threat_intel import ThreatIntelManager
    ti = ThreatIntelManager.__new__(ThreatIntelManager)   # no I/O; poke internals
    import threading
    ti._lock = threading.Lock(); ti._ips = {"8.8.8.8", "45.9.148.1"}; ti._origin = {}
    _check("match_ip skips 8.8.8.8", ti.match_ip("8.8.8.8") is None)
    _check("match_ip still hits real C2", ti.match_ip("45.9.148.1") is not None)


def test_benign_os_autorun() -> None:
    print("[3] benign OS autorun")
    sys32 = r"C:\Windows\System32"
    _check("services.exe -> svchost is benign",
           is_benign_os_autorun(fr"{sys32}\services.exe", fr"{sys32}\svchost.exe"))
    _check("TrustedInstaller autorun is benign",
           is_benign_os_autorun(r"C:\Windows\servicing\TrustedInstaller.exe", fr"{sys32}\x.exe"))
    _check("trusted writer -> %TEMP% still FLAGS (abuse case)",
           not is_benign_os_autorun(fr"{sys32}\services.exe",
                                    r"C:\Users\u\AppData\Local\Temp\evil.exe"))
    _check("untrusted writer never benign",
           not is_benign_os_autorun(r"C:\Users\u\Downloads\mal.exe", fr"{sys32}\x.exe"))


def test_engine_self_exclusion() -> None:
    print("[4] engine self-exclusion (does not touch real threats)")
    os.environ["VALKYRIE_DATA_DIR"] = tempfile.mkdtemp()
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.telemetry import TelemetryEvent, CAT_NETWORK, CAT_PROCESS, SEV_HIGH
    eng = EdrEngine(Store()); eng.start()

    own = TelemetryEvent(category=CAT_NETWORK, activity="connect", action="flagged",
                         actor_pid=1, actor_name="valkyrie.exe",
                         target={"ip": "8.8.8.8", "port": 53}, severity=SEV_HIGH,
                         reason="own resolver", source="network_collector",
                         labels=["threat_intel_ip"])
    _check("valkyrie.exe telemetry suppressed", eng.ingest_telemetry(own) is None)

    threat = TelemetryEvent(category=CAT_PROCESS, activity="exec", action="flagged",
                            actor_pid=2, actor_name="rundll32.exe",
                            actor_path=r"C:\Windows\System32\rundll32.exe",
                            target={}, severity=SEV_HIGH, reason="lsass dump",
                            source="process_collector", labels=["lolbin"])
    _check("real threat still creates an incident", eng.ingest_telemetry(threat) is not None)


def main() -> int:
    print("=" * 60)
    print("False-positive suppression tests")
    print("=" * 60)
    test_is_self()
    test_public_resolvers()
    test_benign_os_autorun()
    test_engine_self_exclusion()
    print("-" * 60)
    if _failures:
        print(f"{_failures} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
