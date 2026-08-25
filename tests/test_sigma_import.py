#!/usr/bin/env python3
"""Sigma rule import (valkyrie/edr/sigma_import.py).

SigmaHQ gives away 3000+ detection rules. The value of this importer is not
that it can convert them - that part is easy - it is that it REFUSES the ones
that would break the user's machine or mean something different from what their
author wrote. So the suite is mostly about the refusals.

The keystone [FP] proves the non-negotiable gate: a Sigma rule that is perfectly
valid upstream but fires on a legitimate command here is rejected outright.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.edr.sigma_import import (  # noqa: E402
    convert, import_rules, summarise, SigmaVerdict,
)


def _sig(**kw):
    base = {
        "title": "Test Rule", "id": "abc-123", "level": "high",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"Image|endswith": "\\rundll32.exe",
                                    "CommandLine|contains": "javascript:"},
                      "condition": "selection"},
        "tags": ["attack.defense_evasion", "attack.t1218.011"],
    }
    base.update(kw)
    return base


def main() -> int:
    c = Checks("Sigma import — take the community's content, safely", expect_min=16)

    # ================================================================ [1]
    print("\n[1] a clean process_creation rule converts with full fidelity")
    rule, verdict, _ = convert(_sig())
    c.check("converted", verdict == SigmaVerdict.IMPORTED and rule is not None)
    c.check("Image|endswith -> images (basename)", rule.images == ("rundll32.exe",))
    c.check("CommandLine|contains -> cmd_all", rule.cmd_all == ("javascript:",))
    c.check("ATT&CK tag -> technique", rule.technique == "T1218.011")
    c.check("level high -> severity high", rule.severity == "high")
    c.check("attribution preserved (DRL 1.1 asks for it)",
            "SigmaHQ" in rule.reason and "abc-123" in rule.reason)

    # ================================================================ [FP] KEYSTONE
    print("\n[FP] THE NON-NEGOTIABLE GATE: a valid upstream rule that breaks a "
          "REAL program is rejected")
    # Perfectly reasonable upstream: "git.exe cloning over https". Here it hits
    # a legitimate developer command in the benign corpus.
    noisy = _sig(title="Suspicious Git Clone",
                 detection={"selection": {"Image|endswith": "\\git.exe",
                                          "CommandLine|contains": "clone"},
                            "condition": "selection"})
    res = import_rules([noisy])
    c.check("rejected for false positives",
            res[0].verdict == SigmaVerdict.REJECT_FP)
    c.check("the offending benign command is named (auditable)",
            len(res[0].fired_on) >= 1)
    c.check("the reason states imported content gets MORE scrutiny",
            any("scrutiny" in r for r in res[0].reasons))

    # ================================================================ [2]
    print("\n[2] unsupported logsource is SKIPPED, never approximated")
    _, v, reasons = convert(_sig(logsource={"category": "registry_set"}))
    c.check("registry_set skipped", v == SigmaVerdict.SKIP_LOGSOURCE)
    c.check("reason explains why approximating would be wrong",
            any("change what the author" in r for r in reasons))

    # ================================================================ [3]
    print("\n[3] Sigma logic we cannot express EXACTLY is skipped, not guessed")
    _, v, _ = convert(_sig(detection={"selection": {"Image|endswith": "\\a.exe"},
                                      "filter": {"User": "SYSTEM"},
                                      "condition": "selection and not filter"}))
    c.check("'and not filter' skipped", v == SigmaVerdict.SKIP_CONDITION)
    _, v2, _ = convert(_sig(detection={
        "selection": {"CommandLine|contains": ["-enc", "-e", "-ec"]},
        "condition": "selection"}))
    c.check("multi-value CommandLine (OR) skipped rather than ANDed",
            v2 == SigmaVerdict.SKIP_CONDITION)

    # ================================================================ [4]
    print("\n[4] hunting-grade rules are not imported as detections")
    _, v, _ = convert(_sig(level="low"))
    c.check("level low skipped", v == SigmaVerdict.SKIP_LEVEL)
    _, v, _ = convert(_sig(level="informational"))
    c.check("level informational skipped", v == SigmaVerdict.SKIP_LEVEL)

    # ================================================================ [5]
    print("\n[5] a rule keying on data Valkyrie does not carry is skipped")
    _, v, _ = convert(_sig(detection={"selection": {"Hashes|contains": "MD5=x"},
                                      "condition": "selection"}))
    c.check("hash-only rule skipped", v == SigmaVerdict.SKIP_NO_FIELDS)

    # ================================================================ [6]
    print("\n[6] duplicates do not shadow tuned local content")
    res = import_rules([_sig(), _sig(title="Different Title")])
    c.check("the second identical shape is skipped as duplicate",
            res[1].verdict == SigmaVerdict.SKIP_DUPLICATE)

    # ================================================================ [7]
    print("\n[7] a malformed corpus never crashes the importer")
    try:
        res = import_rules([{}, {"title": "x"}, None, _sig()])
        c.check("malformed entries are skipped, good ones still import",
                any(r.imported for r in res))
    except Exception as exc:   # noqa: BLE001
        c.fail("malformed entries are skipped, good ones still import", repr(exc))

    # ================================================================ [8]
    print("\n[8] summarise reports the honest funnel")
    res = import_rules([_sig(), _sig(level="low"), _sig(logsource={"category": "dns"})])
    s = summarise(res)
    c.check("summary counts the total", s["total"] == 3)
    c.check("summary counts only what actually imported", s["imported"] == 1)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
