#!/usr/bin/env python3
"""Authenticode signature state (valkyrie/signature.py) and the rules on it.

Signature state is the one signal here that describes what a binary IS rather
than what it did, so it generalises to payloads nobody has written a rule for.
That also makes it dangerous: a wrong answer does not produce a missed
detection, it produces a false positive against real software.

Three keystones:

  [CATALOG] most of Windows is signed by CATALOG, not in-place. Measured before
        this was implemented: cmd.exe and notepad.exe both reported UNSIGNED.
        Any "unsigned binary" rule would have fired on half the operating
        system.
  [FAIL-CLOSED] UNKNOWN is not UNSIGNED. A locked file or an exhausted budget
        must never satisfy a signature rule, or a transient read failure
        manufactures a detection.
  [BUDGET] verification is bounded in wall-clock time. The docstring promising
        "never blocks" is not an implementation; this project has already lost
        a night to a path that blocked for 253 seconds.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file  # noqa: E402
import valkyrie.signature as S  # noqa: E402
from valkyrie.behavioral_rules import Rule, RULES, match_process  # noqa: E402


def main() -> int:
    c = Checks("Authenticode signature state — the generalising signal", expect_min=20)

    # --- platform-independent logic first ---------------------------------
    print("\n[FAIL-CLOSED] KEYSTONE: 'we could not check' must never satisfy a "
          "signature rule")
    r = Rule("t-unsigned", "T1036", "high", "t", "test",
             images=("svchost.exe",), signed="not_trusted")
    c.check("unsigned satisfies not_trusted",
            r.matches("svchost.exe", "x.exe", "svchost.exe", "", "unsigned"))
    c.check("untrusted satisfies not_trusted",
            r.matches("svchost.exe", "x.exe", "svchost.exe", "", "untrusted"))
    c.check("trusted does NOT",
            not r.matches("svchost.exe", "x.exe", "svchost.exe", "", "trusted"))
    c.check("UNKNOWN does NOT (fail closed)",
            not r.matches("svchost.exe", "x.exe", "svchost.exe", "", "unknown"))
    c.check("absent signature data does NOT (fail closed)",
            not r.matches("svchost.exe", "x.exe", "svchost.exe", "", ""))

    exact = Rule("t-untrusted", "T1553", "high", "t", "test", signed="untrusted")
    c.check("an exact-state rule ignores the other bad state",
            not exact.matches("a.exe", "b.exe", "a", "", "unsigned"))
    c.check("an exact-state rule matches its own state",
            exact.matches("a.exe", "b.exe", "a", "", "untrusted"))

    print("\n[1] the shipped signature rules behave")
    hits = {h.rule_id for h in match_process(
        "svchost.exe", "explorer.exe", "svchost.exe",
        r"C:\Users\bob\AppData\Local\Temp\svchost.exe", "unsigned")}
    c.check("an UNSIGNED svchost raises the masquerade rule",
            "masquerade-unsigned-system-binary" in hits)
    hits = {h.rule_id for h in match_process(
        "svchost.exe", "services.exe", "svchost.exe -k netsvcs",
        r"C:\Windows\System32\svchost.exe", "trusted")}
    c.check("the REAL svchost raises nothing", not hits)
    hits = {h.rule_id for h in match_process(
        "svchost.exe", "explorer.exe", "svchost.exe",
        r"C:\Windows\System32\svchost.exe", "unknown")}
    c.check("an unverifiable svchost raises nothing (fail closed)", not hits)

    # a developer's own unsigned build must not raise an incident
    hits = [h for h in match_process(
        "mytool.exe", "cmd.exe", "mytool.exe --run",
        r"C:\Users\bob\AppData\Local\Temp\mytool.exe", "unsigned")]
    c.check("an unsigned dev build in temp is CONTEXT only, never an incident",
            hits and all(h.severity.lower() == "low" for h in hits))

    print("\n[2] classification maps real Win32 status codes, and guesses at none")
    c.check("0 -> trusted", S._classify(0).trust is S.Trust.TRUSTED)
    c.check("TRUST_E_NOSIGNATURE -> unsigned",
            S._classify(0x800B0100).trust is S.Trust.UNSIGNED)
    c.check("TRUST_E_BAD_DIGEST (tampered) -> untrusted",
            S._classify(0x80096010).trust is S.Trust.UNTRUSTED)
    c.check("CERT_E_REVOKED -> untrusted",
            S._classify(0x800B010C).trust is S.Trust.UNTRUSTED)
    c.check("an UNRECOGNISED status -> unknown, never a guess",
            S._classify(0x00001234).trust is S.Trust.UNKNOWN)

    print("\n[3] the cache is keyed on file IDENTITY, not path")
    tmpd = Path(tempfile.mkdtemp())
    f = tmpd / "swap.bin"
    f.write_bytes(b"A" * 64)
    k1 = S._identity(str(f))
    os.utime(f, (0, 0))
    f.write_bytes(b"B" * 128)          # same path, different content
    k2 = S._identity(str(f))
    c.check("replacing the file at a known path changes the cache key", k1 != k2)
    c.check("a missing path has no identity", S._identity(str(tmpd / "nope")) is None)

    print("\n[4] nothing here ever raises")
    for bad in (None, "", r"C:\does\not\exist.exe", "\x00bad"):
        try:
            info = S.verify(bad)
            c.check(f"verify({bad!r}) -> UNKNOWN, no exception",
                    info.trust is S.Trust.UNKNOWN)
        except Exception as exc:   # noqa: BLE001
            c.fail(f"verify({bad!r}) -> UNKNOWN, no exception", repr(exc))

    # ---------------- Windows-only, against REAL binaries -----------------
    if sys.platform != "win32" or not S._AVAILABLE:
        c.skip("[CATALOG] real-binary verification", "not Windows / API absent")
        c.skip("[BUDGET] real-binary budget", "not Windows / API absent")
        return c.finish()

    print("\n[CATALOG] KEYSTONE: catalog-signed system binaries are TRUSTED, "
          "not 'unsigned'")
    S.clear_cache()
    S._BUDGET_SPEND_S = 999.0          # measure truth, not the budget
    catalog_cases = [r"C:\Windows\System32\cmd.exe",
                     r"C:\Windows\System32\notepad.exe",
                     r"C:\Windows\System32\rundll32.exe"]
    results = {p: S.verify(p) for p in catalog_cases}
    c.check("cmd.exe / notepad.exe / rundll32.exe all verify as TRUSTED "
            "(they carry NO embedded signature)",
            all(i.trust is S.Trust.TRUSTED for i in results.values()))
    c.check("and they got there via the CATALOG path",
            any("catalog" in i.detail for i in results.values()))

    print("\n[5] a genuinely unsigned file is reported UNSIGNED, not trusted")
    junk = tmpd / "notabinary.exe"
    junk.write_bytes(b"this is not a signed pe file")
    c.check("an arbitrary file is UNSIGNED",
            S.verify(str(junk)).trust is S.Trust.UNSIGNED)

    print("\n[BUDGET] KEYSTONE: verification is time-bounded, and exhausting "
          "the budget degrades to UNKNOWN rather than stalling")
    S.clear_cache()
    S._BUDGET_SPEND_S = 0.0            # nothing may be spent
    S._budget_window_start = S._monotonic()
    S._budget_spent = 0.0
    info = S.verify(r"C:\Windows\System32\cmd.exe")
    c.check("with no budget, verification returns UNKNOWN",
            info.trust is S.Trust.UNKNOWN)
    c.check("and says so, so it is not mistaken for a real verdict",
            "budget" in info.detail)
    c.check("a budget-skipped answer is NOT cached (one busy second must not "
            "blind us to a binary forever)",
            S._identity(r"C:\Windows\System32\cmd.exe") not in S._CACHE)

    S._BUDGET_SPEND_S = 999.0
    S._budget_spent = 0.0
    c.check("with budget restored the same file verifies normally",
            S.verify(r"C:\Windows\System32\cmd.exe").trust is S.Trust.TRUSTED)

    # ================================================== [SELF-DECEPTION]
    print("\n[SELF-DECEPTION] a false-positive measurement taken while the "
          "budget is starving verification proves NOTHING about these rules")
    #
    # This is here because it actually happened. A live false-positive sweep was
    # run across 122 real processes and reported "0 false positives, signature
    # rules included". The same run's own output said {'trusted': 18,
    # 'unknown': 104} - the budget had throttled 104 of 122 binaries to UNKNOWN,
    # and signature rules fail closed on UNKNOWN. They were structurally
    # INCAPABLE of firing. Their silence was reported as evidence of safety when
    # it was evidence of nothing at all.
    #
    # Re-run with the budget lifted: 115 trusted, 6 genuinely unsigned, still 0
    # false positives. THAT is the measurement that means something.
    #
    # The property below makes the trap explicit, so a future sweep that sees
    # mostly-UNKNOWN state is understood as an untested run rather than a clean
    # one.
    sig_rules = [r for r in RULES if getattr(r, "signed", "")]
    c.check("there are signature-dependent rules to reason about", len(sig_rules) >= 1)
    c.check("EVERY signature rule is silent on UNKNOWN — so an FP sweep with "
            "unresolved signatures cannot exonerate them",
            all(not r.matches("svchost.exe", "explorer.exe", "svchost.exe",
                              r"c:\users\public\svchost.exe", "unknown")
                for r in sig_rules))
    c.check("and the same rules DO fire once the state is actually resolved "
            "(proving the silence above was the budget, not the rule)",
            any(r.matches("svchost.exe", "explorer.exe", "svchost.exe",
                          r"c:\users\public\svchost.exe", "unsigned")
                for r in sig_rules))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
