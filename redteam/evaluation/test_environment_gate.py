"""Proves the host-precondition gate actually withholds credit.

Why this file exists
--------------------
Three techniques (T1055 process injection, both T1003.001 LSASS cases) were
promoted from `predicted_tier_b="CONDITIONAL"` to `"DETECT"` on 2026-08-04,
because Sysmon is now installed here and the real classifiers were executed and
do fire. That promotion moved the Tier A score from 36/40 (90.0%) to 39/40
(97.5%).

A promotion like that is only honest if the condition it depended on is still
enforced somewhere. The whole point of `Technique.requires` +
`environment.check_requirements` is that on a host WITHOUT Sysmon those three
stop being credited automatically. If that gate silently failed open, the
catalog would claim 97.5% on a bare Windows box with literally zero visibility
into process injection -- a worse lie than the CONDITIONAL label ever was,
because it looks verified.

A gate that has never been observed to reject anything is not known to work.
On this host every precondition is satisfied, so the "not met" branch never
executes during a normal run and would stay untested forever. This file
supplies the negative control by probing synthetic hosts.

Run:  PYTHONUTF8=1 python redteam/evaluation/test_environment_gate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent.parent / "tests"))

from harness import Checks                                        # noqa: E402
from environment import (SysmonEnvironment, check_requirements,    # noqa: E402
                         probe_sysmon)
from catalog import all_in_scope                                   # noqa: E402

# The three techniques the promotion applies to, and the EID each depends on.
PROMOTED = {
    "evasion-process-injection": "sysmon_eid8",
    "cred-lsass-comsvcs": "sysmon_eid10",
    "cred-lsass-procdump": "sysmon_eid10",
}


def _host(present=True, live=True, eids=(1, 3, 7, 8, 10)) -> SysmonEnvironment:
    return SysmonEnvironment(
        present=present,
        service_state="Running" if present else "not-found",
        log_enabled=live, log_record_count=1000 if live else 0,
        newest_event_age_seconds=1.0 if live else None,
        collection_live=live, configured_eids=tuple(eids),
    )


def main() -> int:
    c = Checks("Host-precondition gate (negative controls)")

    # ---- the catalog still says what we think it says ----------------------
    by_id = {t.id: t for t in all_in_scope()}
    for tid, token in PROMOTED.items():
        t = by_id.get(tid)
        c.check(f"{tid} is in the in-scope catalog", t is not None)
        if t is None:
            continue
        c.check(f"{tid} is labelled DETECT (was CONDITIONAL)",
                t.predicted_tier_b == "DETECT")
        c.check(f"{tid} carries requires=({token!r},) — the promotion is gated",
                tuple(t.requires) == (token,))

    # A DETECT label with no `requires` on a Sysmon-only path would be the
    # exact regression this file exists to catch.
    for tid, token in PROMOTED.items():
        t = by_id.get(tid)
        if t is not None:
            c.check(f"{tid} would NOT be credited on a Sysmon-less host",
                    not check_requirements(tuple(t.requires), _host(present=False))[0])

    # ---- the gate rejects for each distinct reason -------------------------
    full = _host()
    for token in ("sysmon_eid8", "sysmon_eid10"):
        ok, why = check_requirements((token,), full)
        c.check(f"{token}: satisfied on a fully-equipped host", ok and why == "")

        ok, why = check_requirements((token,), _host(present=False))
        c.check(f"{token}: REJECTED when Sysmon absent (reason given: {why!r})",
                not ok and "not installed" in why)

        ok, why = check_requirements((token,), _host(live=False))
        c.check(f"{token}: REJECTED when service runs but collection is dead "
                f"(reason: {why!r})",
                not ok and "not live" in why)

    # Sysmon healthy, but the config does not emit that specific EID. This is
    # the subtle one: the service is Running and events ARE flowing, so any
    # check that stopped at "is Sysmon up?" would wrongly pass.
    ok, why = check_requirements(("sysmon_eid8",), _host(eids=(1, 3, 7, 10)))
    c.check(f"sysmon_eid8: REJECTED when CreateRemoteThread is not in the "
            f"active config, despite Sysmon being healthy (reason: {why!r})",
            not ok and "never emitted" in why)

    ok, why = check_requirements(("sysmon_eid10",), _host(eids=(1, 3, 7, 8)))
    c.check("sysmon_eid10: REJECTED when ProcessAccess is not in the active "
            "config, despite Sysmon being healthy",
            not ok and "never emitted" in why)

    # ---- unknown tokens must fail CLOSED ----------------------------------
    # A typo'd requirement must never behave like "no requirement" and hand out
    # free credit. This is the failure mode that would be invisible in review.
    ok, why = check_requirements(("sysmon_eid99",), full)
    c.check(f"unknown EID fails CLOSED (reason: {why!r})", not ok)
    ok, why = check_requirements(("sysmonn_eid8",), full)
    c.check("typo'd token fails CLOSED rather than being ignored",
            not ok and "unknown precondition" in why)

    # An empty requirement set is not a rejection - most techniques have none.
    ok, why = check_requirements((), _host(present=False))
    c.check("no requirements => met, even on a bare host", ok)

    # ---- all-or-nothing across multiple tokens ----------------------------
    ok, _ = check_requirements(("sysmon_eid8", "sysmon_eid10"),
                               _host(eids=(1, 3, 7, 10)))
    c.check("a multi-token requirement fails if ANY token is unmet", not ok)

    # ---- and the real host is described accurately -------------------------
    # Not an assertion about what Sysmon SHOULD be - just that the probe
    # returns a coherent answer and agrees with itself.
    real = probe_sysmon()
    c.check(f"probe_sysmon() returns a coherent snapshot "
            f"(present={real.present}, live={real.collection_live}, "
            f"eids={list(real.configured_eids)})",
            isinstance(real.present, bool)
            and isinstance(real.configured_eids, tuple))
    for eid in (8, 10):
        expected = (real.present and real.collection_live
                    and eid in real.configured_eids)
        c.check(f"provides({eid}) agrees with its own component facts",
                real.provides(eid) == expected)
        if not real.provides(eid):
            c.check(f"provides({eid}) is False => why_not() explains it",
                    bool(real.why_not(eid)))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
