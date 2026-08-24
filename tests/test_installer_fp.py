#!/usr/bin/env python3
"""Installer false-positive gate (valkyrie/trust.is_reputable_app_noise).

A signed, reputable, non-LOLBin app/installer spawns many child processes doing
benign work — that must NOT correlate into a fake "N-tactic multi-stage attack"
(the python_setup.exe → "5 tactics across 10 processes" FP). But the gate must
NEVER hide a real threat: PowerShell/LOLBin chains, high-severity steps, and
unsigned binaries all still correlate. These pin exactly that boundary.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import valkyrie.trust as trust
from valkyrie.telemetry import severity_rank

_fail = 0
_HIGH = severity_rank("high")


def _check(label, ok):
    global _fail
    if not ok:
        _fail += 1
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}")


def _noise(name, path, sev):
    return trust.is_reputable_app_noise(name, path, severity_rank(sev), _HIGH)


def main() -> int:
    print("=" * 60)
    print("Installer false-positive gate")
    print("=" * 60)

    # Pretend the third-party installer is validly signed; nothing else is.
    signed = r"C:\Users\u\Downloads\python_setup.exe"
    orig = trust.is_signed_reputable
    trust.is_signed_reputable = lambda p: p == signed  # type: ignore
    try:
        print("[1] signed reputable non-LOLBin installer noise is gated OUT of chains")
        _check("medium installer detection = benign noise (won't chain)",
               _noise("python_setup.exe", signed, "medium"))
        _check("low installer detection = benign noise",
               _noise("python_setup.exe", signed, "low"))

        print("[2] the gate NEVER hides a real threat")
        _check("HIGH severity from the same signed app STILL chains",
               not _noise("python_setup.exe", signed, "high"))
        _check("critical from the same signed app STILL chains",
               not _noise("python_setup.exe", signed, "critical"))
        _check("a LOLBin (powershell, also signed) ALWAYS chains",
               not _noise("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "medium"))
        _check("cmd.exe (LOLBin) always chains",
               not _noise("cmd.exe", r"C:\Windows\System32\cmd.exe", "medium"))
        _check("an UNSIGNED temp binary always chains",
               not _noise("evil.exe", r"C:\Users\u\AppData\Local\Temp\evil.exe", "medium"))
        _check("a System32 OS binary is not 'app noise' (handled elsewhere)",
               not _noise("services.exe", r"C:\Windows\System32\services.exe", "medium"))

        print("[3] engine wiring: benign app noise is skipped by _correlate_chain")
        import tempfile, os as _os
        _os.environ["VALKYRIE_DATA_DIR"] = tempfile.mkdtemp()
        from valkyrie.store import Store
        from valkyrie.edr import EdrEngine
        from valkyrie.telemetry import TelemetryEvent, CAT_PROCESS, SEV_MEDIUM
        eng = EdrEngine(Store()); eng.start()
        # Two different tactics from the signed installer → must NOT form a chain.
        for tech in ("T1059 — Command & Scripting Interpreter",
                     "T1547.001 — Registry Run Keys / Startup Folder"):
            eng.ingest_telemetry(TelemetryEvent(
                category=CAT_PROCESS, activity="exec", action="flagged",
                actor_pid=10, actor_name="python_setup.exe", actor_path=signed,
                target={}, severity=SEV_MEDIUM, reason="install activity",
                source="process_collector", labels=["lolbin"],
                fields={"technique": tech}))
        chains = [i for i in eng.list_incidents() if i["category"] == "attack_chain"]
        _check("signed installer did NOT raise an attack_chain incident", len(chains) == 0)
    finally:
        trust.is_signed_reputable = orig  # type: ignore

    print("-" * 60)
    if _fail:
        print(f"{_fail} check(s) FAILED.")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
