#!/usr/bin/env python3
"""Hard vetoes on autonomous action (valkyrie/edr/invariants.py).

Two properties are being pinned:

  1. An invariant is CATEGORICAL. There is no confidence, profile or severity
     at which a forbidden action becomes permitted. Anything that can be
     outvoted belongs in scoring, not here.
  2. The built-in floor is not user-removable, and it covers both incidents
     that actually happened on this host (adapter/WiFi) plus the OS processes
     whose termination bugchecks Windows.

Nothing here executes a responder.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def main() -> int:
    c = Checks("autonomous-action invariants (hard vetoes)", expect_min=16)

    from valkyrie.edr import invariants as I

    # ------------------------------------------------------------------ [1]
    print("\n[1] the two outages that actually happened on this machine")
    for tgt in ("Wi-Fi", "Wireless Network Adapter", "Intel Wi-Fi 6 AX201",
                "Ethernet Adapter"):
        inv = I.check("isolate_host", tgt)
        c.check(f"network action on {tgt!r} is VETOED", inv is not None)

    c.check("the veto applies to ANY action, not just the one that caused it "
            "(mac_randomizer and isolate_host both reached the adapter)",
            I.check("mac_randomize", "Wi-Fi") is not None)

    # ------------------------------------------------------------------ [2]
    print("\n[2] the most reachable catastrophic action in the product")
    inv = I.check("kill_process", "lsass.exe")
    c.check("kill_process on lsass.exe is VETOED — credential-dumping rules "
            "point AT lsass, so a confident T1003.001 hit would otherwise "
            "aim the kill responder at an instant bugcheck", inv is not None)
    c.check("the reason explains the bugcheck rather than just saying 'no'",
            inv is not None and "bugcheck" in inv.reason.lower())

    for p in ("csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
              "smss.exe"):
        c.check(f"kill_process on {p} is VETOED", I.check("kill_process", p) is not None)

    c.check("matching is case-insensitive (LSASS.EXE is the same process)",
            I.check("kill_process", "LSASS.EXE") is not None)

    # ------------------------------------------------------------------ [3]
    print("\n[3] self-preservation")
    c.check("Valkyrie may not kill its own engine — a detector firing on the "
            "agent's own behaviour would otherwise be an evasion primitive",
            I.check("kill_process", "valkyrie.exe") is not None)

    # ------------------------------------------------------------------ [4]
    print("\n[4] ordinary actions are NOT vetoed — this must not become a "
          "blanket 'do nothing'")
    for action, tgt in (("kill_process", "evil.exe"),
                        ("block_domain", "malware.example"),
                        ("isolate_host", "workstation-7")):
        c.check(f"{action} on {tgt!r} is permitted", I.check(action, tgt) is None)

    # ------------------------------------------------------------------ [5]
    print("\n[5] categorical: enforce() raises and carries the reason")
    try:
        I.enforce("kill_process", "lsass.exe")
        c.check("enforce() raises Veto on a forbidden action", False)
    except I.Veto as v:
        c.check("enforce() raises Veto on a forbidden action", True)
        c.check("the Veto names the invariant, action and target",
                v.invariant.invariant_id and v.action == "kill_process"
                and v.target == "lsass.exe")

    try:
        I.enforce("kill_process", "evil.exe")
        c.check("enforce() is silent on a permitted action", True)
    except I.Veto:
        c.check("enforce() is silent on a permitted action", False)

    # ------------------------------------------------------------------ [6]
    print("\n[6] built-ins are a floor, not a default the user can delete")
    c.check("every built-in is flagged builtin=True",
            all(i.builtin for i in I.BUILTINS))
    before = len([i for i in I.all_invariants() if i.builtin])
    I.save_user([])                      # user clears their own list
    after = len([i for i in I.all_invariants() if i.builtin])
    c.check("clearing user invariants leaves every built-in in place",
            after == before and after >= len(I.BUILTINS))
    c.check("save_user never persists a built-in (so it cannot be edited out "
            "of the file and lost)",
            all(not i.builtin for i in I.load_user()))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
