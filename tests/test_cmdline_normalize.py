#!/usr/bin/env python3
"""Command-line normalization + evasion resistance (valkyrie/cmdline_normalize.py).

The measured problem this closes: before normalization, 5 of 8 trivial
obfuscations defeated the ENTIRE 40-rule IOA engine. A rule engine that only
catches unobfuscated commands catches nothing real.

  [1] Each transform recovers the plaintext it targets
  [2] EVASIVE vs COSMETIC classification (obfuscation is itself a signal)
  [3] EVASION CORPUS — obfuscated attacks must still hit their real rule
  [4] BENIGN CONTROLS — normalization must not invent detections
  [5] Purity/robustness — never raises, bounded, deterministic
  [6] Obfuscation alone (no rule) still reports T1027
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


# (name, image, obfuscated cmdline, ATT&CK id that MUST be recovered)
EVASION_CORPUS = [
    ("caret escaping", "cmd.exe",
     r"n^et us^er hacker /a^dd", "T1136.001"),
    ("token-splitting quotes", "cmd.exe",
     'n"e"t user hacker /add', "T1136.001"),
    ("PowerShell concat", "powershell.exe",
     "& ('ne'+'t') user hacker /add", "T1136.001"),
    ("backtick escaping", "powershell.exe",
     "vssa`dmin delete shadows /all", "T1490"),
    ("char arithmetic", "powershell.exe",
     "[char]118+[char]115+[char]115+[char]97+[char]100+[char]109+[char]105"
     "+[char]110 delete shadows", "T1490"),
    ("char array", "powershell.exe",
     "[char[]](118,115,115,97,100,109,105,110) delete shadows", "T1490"),
    ("full-width unicode", "cmd.exe",
     "ｎｅｔ user hacker /add", "T1136.001"),
    ("zero-width joiner", "cmd.exe",
     "n\u200be\u200bt user hacker /add", "T1136.001"),
    ("env var expansion", "cmd.exe",
     r"%COMSPEC% /c vssadmin delete shadows", "T1490"),
    ("base64 -enc payload", "powershell.exe",
     "-enc dgBzAHMAYQBkAG0AaQBuACAAZABlAGwAZQB0AGUAIABzAGgAYQBkAG8AdwBzAA==",
     "T1490"),
    ("combined caret+quotes", "cmd.exe",
     'w^evtu"t"il c^l Security', "T1070.001"),
    ("whitespace padding", "vssadmin.exe",
     "vssadmin     delete      shadows", "T1490"),
]

# Command lines that are NOT attacks. Normalization must not turn any of these
# into a detection — this is the false-positive boundary and the reason
# token-splitting quotes are removed surgically rather than globally.
BENIGN_CONTROLS = [
    ("chrome.exe", r'"C:\Program Files\Google\Chrome\chrome.exe" --profile-directory=Default'),
    ("msbuild.exe", r'msbuild.exe "C:\Users\dev\My Project\app.sln" /p:Configuration=Release'),
    ("cmd.exe", r'copy "C:\Program Files\App\data.txt" "D:\Backup\data.txt"'),
    ("powershell.exe", "Get-ChildItem 'C:\\Users' | Where-Object { $_.Name -like 'a*' }"),
    ("robocopy.exe", r'robocopy "C:\Program Files (x86)\App" D:\Backup /MIR'),
    ("git.exe", r'git commit -m "fix: net user listing was flagged"'),
    ("cmd.exe", r'echo Building in %TEMP% directory'),
    ("setup.exe", r'setup.exe /S /D=C:\Program Files\MyApp'),
    ("python.exe", r'python -c "print(\'hello\' + \'world\')"'),
    ("cmd.exe", r'findstr /C:"net user" audit_policy.txt'),
]


def main() -> int:
    from valkyrie.cmdline_normalize import (
        normalize_cmdline, Normalized, COSMETIC, EVASIVE)
    from valkyrie.behavioral_rules import classify_behavior

    print("\n=== command-line normalization + evasion resistance ===\n")

    print("[1] Each transform recovers its plaintext")
    _check("caret", "net user" in normalize_cmdline("n^et us^er").text)
    _check("backtick", "vssadmin" in normalize_cmdline("vssa`dmin").text)
    _check("token-splitting quotes", "net" in normalize_cmdline('n"e"t').text)
    _check("concat (parens consumed)",
           "net" in normalize_cmdline("('ne'+'t')").text)
    _check("char arithmetic",
           "net" in normalize_cmdline("[char]110+[char]101+[char]116").text)
    _check("char array",
           "net" in normalize_cmdline("[char[]](110,101,116)").text)
    _check("full-width unicode", "net" in normalize_cmdline("ｎｅｔ").text)
    _check("zero-width stripped", "net" in normalize_cmdline("n\u200be\u200bt").text)
    _check("env var", "cmd.exe" in normalize_cmdline("%COMSPEC%").text.lower())
    _check("env substring form",
           normalize_cmdline("%COMSPEC:~0,1%").text.lower().startswith("c"))
    _check("whitespace collapsed",
           normalize_cmdline("a     b").text == "a b")
    _check("short path",
           "program files" in normalize_cmdline(r"C:\PROGRA~1\x").text.lower())
    b64 = normalize_cmdline(
        "-enc dgBzAHMAYQBkAG0AaQBuACAAZABlAGwAZQB0AGUAIABzAGgAYQBkAG8AdwBzAA==")
    _check("base64 -enc decoded into searchable text",
           "vssadmin delete shadows" in b64.text.lower())

    print("\n[2] EVASIVE vs COSMETIC classification")
    _check("caret is EVASIVE", normalize_cmdline("n^et").obfuscated)
    _check("char arithmetic is EVASIVE",
           normalize_cmdline("[char]110+[char]101").obfuscated)
    _check("full-width unicode is EVASIVE", normalize_cmdline("ｎｅｔ").obfuscated)
    _check("plain env var is NOT obfuscation",
           not normalize_cmdline("%COMSPEC% /c dir").obfuscated)
    _check("extra whitespace is NOT obfuscation",
           not normalize_cmdline("dir     C:\\").obfuscated)
    _check("ordinary command reports no transforms",
           not normalize_cmdline("ipconfig /all").changed)
    _check("COSMETIC and EVASIVE are disjoint", not (COSMETIC & EVASIVE))

    print(f"\n[3] EVASION CORPUS — {len(EVASION_CORPUS)} obfuscated attacks "
          f"must reach their real rule")
    recovered = 0
    for name, image, cmd, want_tid in EVASION_CORPUS:
        hit = classify_behavior(image, "cmd.exe", cmd, "")
        got = (hit or {}).get("technique", "")
        ok = hit is not None and want_tid in got
        if ok:
            recovered += 1
        _check(f"{name} -> {want_tid}", ok)
    print(f"\n    EVASION RESISTANCE: {recovered}/{len(EVASION_CORPUS)} "
          f"({100*recovered//len(EVASION_CORPUS)}%)")
    _check("evasion resistance >= 90%",
           recovered >= 0.9 * len(EVASION_CORPUS))

    print(f"\n[4] BENIGN CONTROLS — {len(BENIGN_CONTROLS)} legitimate commands "
          f"must NOT be detected")
    fps = []
    for image, cmd in BENIGN_CONTROLS:
        hit = classify_behavior(image, "explorer.exe", cmd, "")
        if hit is not None:
            fps.append((cmd[:48], hit.get("technique", "")))
        _check(f"benign '{cmd[:44]}'", hit is None)
    _check("ZERO false positives introduced by normalization", not fps)
    if fps:
        for c, t in fps:
            print(f"      FP: {c} -> {t}")

    print("\n[5] Purity / robustness — never raises, bounded, deterministic")
    hostile = [
        "", None, "^" * 5000, "`" * 5000, '"' * 5000,
        "[char]" * 2000, "%" * 5000, "(" * 3000 + ")" * 3000,
        "a" * 100_000, "-enc " + "A" * 50_000,
        "%COMSPEC:~999999,999999%", "[char]99999999999999",
        "\u200b" * 5000, "ｎ" * 5000, "'a'+" * 3000 + "'b'",
    ]
    raised = None
    for h in hostile:
        try:
            r = normalize_cmdline(h)  # type: ignore[arg-type]
            if not isinstance(r, Normalized) or not isinstance(r.text, str):
                raised = f"bad return type for {str(h)[:20]!r}"
        except Exception as exc:
            raised = f"{type(exc).__name__} on {str(h)[:20]!r}: {exc}"
            break
    _check("no hostile input raises or returns a bad type", raised is None)
    if raised:
        print(f"      {raised}")
    _check("output is length-bounded",
           len(normalize_cmdline("a" * 100_000).text) <= 20_000)
    _check("deterministic (same input -> same output)",
           normalize_cmdline("n^et us^er").text
           == normalize_cmdline("n^et us^er").text)

    print("\n[6] Obfuscation with NO matching rule still reports T1027")
    h = classify_behavior("powershell.exe", "explorer.exe",
                          "$a='xyz'+'abc'; $b=[char]65+[char]66", "")
    _check("evasive syntax alone raises T1027",
           h is not None and "T1027" in h.get("technique", ""))
    _check("labeled obfuscated_command",
           h is not None and "obfuscated_command" in h.get("labels", []))
    _check("MEDIUM, not HIGH (suspicion, not conviction)",
           h is not None and h.get("severity") == "medium")
    clean = classify_behavior("powershell.exe", "explorer.exe",
                              "Get-Process | Sort-Object CPU", "")
    _check("clean PowerShell raises nothing", clean is None)

    print("\n[7] A known-bad AND obfuscated command escalates")
    plain = classify_behavior("net.exe", "cmd.exe", "net user hacker /add", "")
    obf = classify_behavior("net.exe", "cmd.exe", "n^et us^er hacker /a^dd", "")
    _check("plain form detected", plain is not None)
    _check("obfuscated form detected", obf is not None)
    _check("obfuscated form is MORE severe than plain "
           "(an admin does not caret-escape)",
           plain is not None and obf is not None
           and obf["severity"] == "high" and plain["severity"] == "medium")

    print("\n" + "=" * 60)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print(f"All checks PASSED "
          f"(evasion {recovered}/{len(EVASION_CORPUS)}, 0 FPs).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
