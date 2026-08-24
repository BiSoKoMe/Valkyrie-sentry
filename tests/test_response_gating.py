#!/usr/bin/env python3
"""ResponseManager wiring: invariant veto, lease grant, cascade record, sweeper.

This is the commit where the autonomy machinery stops being a library and
starts sitting in the dispatch path. The properties that matter:

  * a vetoed action NEVER reaches the responder -- not "is undone after", not
    "is logged and allowed", but is not executed at all;
  * the veto is checked BEFORE the severity floor, because a floor is a
    threshold and an invariant is not;
  * a lease is granted only AFTER enforcement actually succeeded;
  * the sweeper only ever issues RESTORATIVE actions;
  * a failed revert keeps its lease so the next sweep retries, rather than
    stranding the enforcement it exists to lift.

No responder executes for real here: every call is dry_run, or is routed to a
recording fake. Nothing touches this host's firewall, DNS or processes.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


class _FakeResponder:
    """Records what it was asked to do; never touches the host."""

    def __init__(self, actions, status="ok"):
        self.actions = tuple(actions)
        self.status = status
        self.calls: list[tuple] = []

    def handles(self, action):            # pragma: no cover - interface shim
        return action in self.actions

    def execute(self, action, target, *, dry_run=False, ctx=None):
        self.calls.append((action, target, dry_run))
        return self.status, f"fake {action} on {target}"


class _FakeRegistry:
    def __init__(self, responder):
        self._r = responder

    def responder_for(self, action):
        return self._r if action in self._r.actions else None


def main() -> int:
    c = Checks("response gating (invariants, leases, cascade, sweeper)",
               expect_min=14)

    from valkyrie.edr.response import ResponseManager
    from valkyrie.edr import leases as L, cascade as CA

    fake = _FakeResponder(("block_domain", "unblock_domain", "kill_process"))
    mgr = ResponseManager.__new__(ResponseManager)
    mgr._registry = _FakeRegistry(fake)
    mgr._store = None
    mgr._ctx = None

    # ------------------------------------------------------------------ [1]
    print("\n[1] a vetoed action never reaches the responder")
    before = len(fake.calls)
    act = mgr.respond("kill_process", "lsass.exe", dry_run=False,
                      severity="critical")
    c.check("status is 'skipped', not executed", act.status == "skipped")
    c.check("the responder was NEVER called — refused, not undone afterwards",
            len(fake.calls) == before)
    c.check("the result names the invariant", "invariant" in act.result)
    c.check("and explains why rather than just refusing",
            "bugcheck" in act.result.lower())

    # ------------------------------------------------------------------ [2]
    print("\n[2] the veto sits in FRONT of the severity floor")
    # kill_process is irreversible and floors at 'critical'. Passing critical
    # clears the floor, so anything still refusing must be the invariant.
    act = mgr.respond("kill_process", "Wi-Fi", dry_run=False, severity="critical")
    c.check("critical severity clears the floor but the invariant still "
            "refuses — a threshold cannot be allowed to authorise a "
            "categorical prohibition", act.status == "skipped"
            and "invariant" in act.result)

    # ------------------------------------------------------------------ [3]
    print("\n[3] an ordinary target is NOT blocked — this must not become a "
          "blanket refusal")
    before = len(fake.calls)
    act = mgr.respond("kill_process", "evil.exe", dry_run=False, severity="critical")
    c.check("a legitimate kill still executes", len(fake.calls) == before + 1)
    c.check("status is not a refusal", act.status != "skipped")

    # ------------------------------------------------------------------ [4]
    print("\n[4] dry-run never gates and never books anything")
    n_before = len(L.registry())
    act = mgr.respond("block_domain", "evil.example", dry_run=True)
    c.check("dry-run reaches the responder", fake.calls[-1][2] is True)
    c.check("dry-run grants NO lease — nothing was applied to revert",
            len(L.registry()) == n_before)

    # ------------------------------------------------------------------ [5]
    print("\n[5] a real enforcement grants a lease and records to the budget")
    reg = L.registry()
    for lease in list(reg.active()) + list(reg.due()):
        reg.release(lease.lease_id)
    budget_before = len(CA.budget())

    act = mgr.respond("block_domain", "beacon.example", dry_run=False,
                      severity="high", lease_ttl_s=1200.0)
    held = reg.get("block_domain", "beacon.example")
    c.check("a lease is held for the enforcement that just ran", held is not None)
    c.check("it carries the dispatchable inverse",
            held is not None and held.reverse_action == "unblock_domain")
    c.check("the caller's cadence-derived TTL is honoured",
            held is not None and abs((held.expires_at - held.granted_at) - 1200.0) < 1.0)
    c.check("the action was recorded to the cascade budget",
            len(CA.budget()) == budget_before + 1)

    # ------------------------------------------------------------------ [6]
    print("\n[6] the sweeper reverts what has expired, restoratively")
    swept = mgr.sweep_expired_leases(dry_run=False,
                                     now=held.expires_at + 60)
    c.check("the expired lease produced exactly one reverse action",
            len(swept) == 1)
    c.check("and it is the RESTORATIVE direction (unblock, never block)",
            swept and swept[0].action == "unblock_domain")
    c.check("the lease is released once the revert succeeded",
            reg.get("block_domain", "beacon.example") is None)

    # ------------------------------------------------------------------ [7]
    print("\n[7] a FAILED revert keeps its lease so the next sweep retries")
    failing = _FakeResponder(("block_domain", "unblock_domain"), status="failed")
    mgr2 = ResponseManager.__new__(ResponseManager)
    mgr2._registry = _FakeRegistry(failing)
    mgr2._store = None
    mgr2._ctx = None
    mgr2.respond("block_domain", "sticky.example", dry_run=False, severity="high")
    # grant landed only if the block "succeeded"; force one explicitly
    reg.grant("block_domain", "sticky.example", ttl_s=60.0, now=1000.0)
    mgr2.sweep_expired_leases(dry_run=False, now=2000.0)
    c.check("a lease whose revert failed is STILL held — dropping it would "
            "strand the enforcement the lease exists to lift",
            reg.get("block_domain", "sticky.example") is not None)

    for lease in list(reg.active()) + list(reg.due()):
        reg.release(lease.lease_id)
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
