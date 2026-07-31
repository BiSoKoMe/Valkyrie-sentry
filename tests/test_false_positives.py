"""Regression locks for the false positives found on real hardware.

A live VM run produced strong detection but a wall of false positives: Valkyrie
flagged Windows Update, Windows Defender, Edge's updater, SmartScreen, its own
installer, and every reverse-DNS lookup as suspicious. For this product a false
positive is the cardinal sin — a lawyer drowning in scary alerts about Windows
Update cannot see the one real attack, and in blocking mode an FP breaks a real
site or app.

Every check here asserts the pair that matters: the legitimate thing is NO
LONGER flagged, AND a real threat of the *same shape* still fires. A fix that
only did the first half would be worse than the bug — it would be a hole.

The four classes, each traced to source:
  1. reverse-DNS / local names raising baseline-anomaly + beacon incidents
  2. OS self-maintenance (TrustedInstaller/Defender/Edge) raising persistence
  3. signed OS binaries (SmartScreen) scored as name-masquerade / obfuscation
  4. installers/uninstallers in temp/downloads raising a standalone incident
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie import trust
from valkyrie.behavior_score import score_process
from valkyrie.edr.builtin import AnomalyDetection, BeaconDetection
from valkyrie.etw.sysmon import classify_sysmon
from valkyrie.popular_domains import is_infrastructure_domain
from valkyrie.process_telemetry import classify_process
from valkyrie.telemetry import SEV_MEDIUM, severity_rank


def _incident(severity: str, action: str = "observed") -> bool:
    """Mirror engine.py:164 — an event alerts only at >= medium or flagged."""
    return severity_rank(severity) >= severity_rank(SEV_MEDIUM) or action == "flagged"


def _dns_event(domain, cat, reason, decision="flagged"):
    return {"domain": domain, "decision": decision, "process_name": "svchost.exe",
            "process_pid": 0, "raw_category": cat, "suspicion": 0.0, "reason": reason}


def main() -> int:
    c = Checks("false positives", expect_min=25)

    # ── The trust primitive it all rests on ─────────────────────────────
    print("\n[0] trusted-path judgement (by path, never by name)")
    c.check("Windows dir is trusted", trust.is_trusted_os_path(r"C:\WINDOWS\servicing\TrustedInstaller.exe"))
    c.check("Defender platform is trusted",
            trust.is_trusted_os_command(r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MpDefenderCoreService.exe"'))
    c.check("relative driver path is trusted", trust.is_trusted_os_path(r"system32\drivers\WdAiNisDrv.sys"))
    c.check("Edge updater command is trusted",
            trust.is_trusted_os_command(r'"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\1\Installer\setup.exe" --on-logon'))
    # the boundaries that keep it safe
    c.check("C:\\Windows\\Temp is NOT trusted (world-writable)",
            not trust.is_trusted_os_path(r"C:\Windows\Temp\evil.exe"))
    c.check("System32\\Tasks is NOT trusted", not trust.is_trusted_os_path(r"C:\Windows\System32\Tasks\evil"))
    c.check("a user path is NOT trusted", not trust.is_trusted_os_path(r"C:\Users\x\AppData\Local\Temp\m.exe"))
    c.check("a look-alike is NOT trusted", not trust.is_trusted_os_path(r"C:\notwindows\system32x\e.exe"))

    # ── Class 1: reverse-DNS anomaly + beacon ───────────────────────────
    print("\n[1] reverse-DNS / local names are not a threat signal")
    c.check("in-addr.arpa is infrastructure", is_infrastructure_domain("169.56.49.23.in-addr.arpa"))
    c.check("ip6.arpa is infrastructure", is_infrastructure_domain("a.b.c.ip6.arpa"))
    c.check("a real domain is NOT infrastructure", not is_infrastructure_domain("evil-c2.example.com"))
    a, b = AnomalyDetection(), BeaconDetection()
    c.check("SUPPRESSED: no anomaly incident for reverse-DNS",
            a.analyze(_dns_event("169.56.49.23.in-addr.arpa", "anomaly", "unseen"), None) == [])
    c.check("STILL FIRES: anomaly incident for a real domain",
            len(a.analyze(_dns_event("evil-c2.example.com", "anomaly", "unseen"), None)) == 1)
    c.check("SUPPRESSED: no beacon incident for reverse-DNS",
            b.analyze(_dns_event("77.44.207.4.in-addr.arpa", "intelligence", "beacon regular interval"), None) == [])
    c.check("STILL FIRES: beacon incident for a real domain",
            len(b.analyze(_dns_event("bad.example.com", "intelligence", "beacon regular interval"), None)) == 1)

    # threat-graph "shares infrastructure" — a reverse-DNS name must not inherit
    # the whole PTR namespace as shared infra (found live: 0.65 on every
    # x.in-addr.arpa). A real sibling of a recorded threat must still relate.
    import threading as _th
    from valkyrie.intelligence.threat_graph import ThreatGraph
    g = ThreatGraph.__new__(ThreatGraph)
    g._domains, g._bases, g._subnets, g._prefixes, g._lock = set(), {}, set(), set(), _th.RLock()
    g._index("7.7.7.7.in-addr.arpa", "", "in-addr.arpa", "")   # poison attempt
    g._index("evil.example.com", "1.2.3.4", "example.com", "")
    c.check("SUPPRESSED: reverse-DNS is not 'related' via a shared PTR base",
            g.is_related("168.56.49.23.in-addr.arpa") == 0.0)
    c.check("  ...and a reverse-DNS name never poisons the base bucket",
            g._bases.get("in-addr.arpa", 0) == 0)
    c.check("STILL FIRES: a real sibling of a recorded threat still relates",
            g.is_related("login.example.com") > 0.0)

    # ── Class 2: OS-maintenance persistence ─────────────────────────────
    print("\n[2] OS self-maintenance does not raise persistence incidents")
    legit = classify_sysmon(13, {"TargetObject": r"HKLM\...\CurrentVersion\Run\x",
                                 "Image": r"C:\WINDOWS\servicing\TrustedInstaller.exe",
                                 "Details": r"C:\Windows\System32\foo.exe"})
    c.check("SUPPRESSED: TrustedInstaller autorun is not an incident",
            not _incident(legit["severity"]))
    c.check("  ...and it is labelled trusted_os for the audit trail",
            "trusted_os" in legit["labels"])
    evil = classify_sysmon(13, {"TargetObject": r"HKLM\...\CurrentVersion\Run\x",
                                "Image": r"C:\Users\x\AppData\Local\Temp\dropper.exe",
                                "Details": r"C:\Users\x\evil.exe"})
    c.check("STILL FIRES: a dropper writing an autorun key IS an incident",
            _incident(evil["severity"]))
    startup_legit = classify_sysmon(11, {"TargetFilename": r"C:\Users\x\...\Startup\upd.lnk",
                                         "Image": r"C:\WINDOWS\uus\packages\wuaucltcore.exe"})
    c.check("SUPPRESSED: Windows Update writing Startup is not an incident",
            not _incident(startup_legit["severity"]))
    startup_evil = classify_sysmon(11, {"TargetFilename": r"C:\Users\x\...\Startup\evil.lnk",
                                        "Image": r"C:\Users\x\Downloads\evil.exe"})
    c.check("STILL FIRES: a user binary writing Startup IS an incident",
            _incident(startup_evil["severity"]))

    # ── Class 3: signed OS binary scored as masquerade/obfuscation ──────
    print("\n[3] a signed OS binary is not masquerade or obfuscation")
    fp = score_process("CHXSmartScreen.exe", "services.exe",
                       "CHXSmartScreen.exe -ServerName:App.AppXblob0987654321==",
                       r"c:/windows/systemapps/microsoft.windows.apprep.chxapp_cw5/CHXSmartScreen.exe")
    c.check("SUPPRESSED: SmartScreen does not fire the anomaly nose", not fp.fired())
    # the crown jewel must be untouched: an interpreter in the SAME trusted dir
    real = score_process("powershell.exe", "explorer.exe",
                         "powershell -nop -w hidden -e SQBFAFgAKABOZXctT2JqZWN0KQ==",
                         r"c:/windows/system32/windowspowershell/v1.0/powershell.exe")
    # (the anomaly nose is only one of four classifiers; the full pipeline result
    # is asserted below via classify_sysmon)
    ev = classify_sysmon(1, {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                             "ParentImage": r"C:\Windows\explorer.exe",
                             "CommandLine": "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqZQ==",
                             "ProcessId": "1"})
    c.check("STILL FIRES: powershell -enc from System32 is a real incident",
            _incident(ev["severity"]))
    c.check("  ...and carries the T1027 obfuscation technique",
            "T1027" in (ev.get("technique") or ""))
    # The exemption is PATH-gated, not a blanket name allowlist: the exact same
    # machine-generated name in an untrusted temp dir must still be scored.
    masq = score_process("CHXSmartScreen.exe", "explorer.exe", "CHXSmartScreen.exe",
                         r"c:/users/x/appdata/local/temp/CHXSmartScreen.exe")
    c.check("STILL FIRES: the SAME name in TEMP is still scored (path-gated, not name-gated)",
            any(s.name == "machine_generated_name" for s in masq.signals))

    # ── Class 4: temp/download execution ────────────────────────────────
    print("\n[4] temp/download execution is weak, not a standalone incident")
    sev, _, _ = classify_process("ValkyrieSetup.exe", r"c:/users/x/downloads/ValkyrieSetup.exe", "explorer.exe")
    c.check("SUPPRESSED: an installer in Downloads is not an incident", not _incident(sev))
    sev2, _, _ = classify_process("Un_A.exe", r"c:/users/x/appdata/local/temp/~nsu.tmp/Un_A.exe", "explorer.exe")
    c.check("SUPPRESSED: an NSIS uninstaller in temp is not an incident", not _incident(sev2))
    sev3, _, _ = classify_process("cmd.exe", r"c:/users/x/appdata/local/temp/cmd.exe", "winword.exe")
    c.check("STILL FIRES: a shell from temp spawned by Office IS an incident", _incident(sev3))
    sev4, lbl4, _ = classify_process("regsvr32.exe", r"c:/windows/temp/regsvr32.exe", "explorer.exe")
    c.check("STILL FIRES: a LOLBin from temp IS an incident (corroborated)", _incident(sev4))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
