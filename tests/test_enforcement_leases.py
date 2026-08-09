#!/usr/bin/env python3
"""Time-boxed enforcement leases (valkyrie/edr/leases.py).

The invariant this file defends is the one that makes autonomous enforcement
safe to fire at less than certainty: an automatic action expires unless the
evidence that justified it recurs. A real threat keeps beaconing and renews
its own block; a false positive goes quiet and the block heals itself.

Every check below runs against a throwaway store in a temp dir and executes
NO responder -- leases.py is deliberately execution-free, so all of this is
testable without touching the host's firewall, DNS or processes.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402


def main() -> int:
    c = Checks("enforcement leases (time-boxed autonomous action)", expect_min=20)

    from valkyrie.edr import leases as L
    from valkyrie.edr import reversibility

    td = Path(tempfile.mkdtemp(prefix="valkyrie_leases_"))
    store = td / "leases.json"

    # ---------------------------------------------------------------- [1] --
    print("\n[1] only reversible actions with a dispatchable inverse are leasable")
    r = LeaseRegistryOrSkip(L, store)
    if r is None:
        return 1

    kill = reversibility.get("kill_process")
    c.check("kill_process is registered irreversible", kill is not None and not kill.reversible)
    c.check("kill_process.leasable is False (a terminated process does not come "
            "back at a deadline -- time-boxing it would be a lie in the scheduler)",
            kill is not None and not kill.leasable)
    try:
        r.grant("kill_process", "1234")
        c.check("grant('kill_process') is REFUSED", False)
    except L.LeaseError:
        c.check("grant('kill_process') is REFUSED", True)

    try:
        r.grant("no_such_action_xyz", "t")
        c.check("grant of an action with no reversibility entry is REFUSED", False)
    except L.LeaseError:
        c.check("grant of an action with no reversibility entry is REFUSED", True)

    blk = reversibility.get("block_domain")
    c.check("block_domain declares reverse_action='unblock_domain'",
            blk is not None and blk.reverse_action == "unblock_domain")
    c.check("block_domain.leasable is True", blk is not None and blk.leasable)

    iso = reversibility.get("isolate_host")
    c.check("isolate_host declares reverse_action='release_isolation'",
            iso is not None and iso.reverse_action == "release_isolation")

    unblk = reversibility.get("unblock_domain")
    c.check("unblock_domain is reversible but NOT leasable -- a release must "
            "not auto-re-apply enforcement when its clock runs out",
            unblk is not None and unblk.reversible and not unblk.leasable)

    # ---------------------------------------------------------------- [2] --
    print("\n[2] a lease expires on its own")
    t0 = 1_000_000.0
    lease = r.grant("block_domain", "evil.example", ttl_s=900.0,
                    reason="beaconing", now=t0)
    c.check("granted with the registry's inverse recorded",
            lease.reverse_action == "unblock_domain")
    c.check("not due immediately", not lease.is_due(t0 + 1))
    c.check("not due at 899s", not lease.is_due(t0 + 899))
    c.check("DUE at 901s -- the block lifts itself with no human involved",
            lease.is_due(t0 + 901))
    c.check("due() lists it after expiry", len(r.due(now=t0 + 901)) == 1)
    c.check("active() excludes it after expiry", len(r.active(now=t0 + 901)) == 0)

    # ---------------------------------------------------------------- [3] --
    print("\n[3] recurring evidence RENEWS instead of stacking duplicates")
    again = r.grant("block_domain", "evil.example", ttl_s=900.0, now=t0 + 500)
    c.check("re-granting the same (action,target) keeps ONE lease", len(r) == 1)
    c.check("same lease_id (renewed, not replaced)", again.lease_id == lease.lease_id)
    c.check("renewals incremented", again.renewals == 1)
    c.check("deadline restarts from the NEW observation, not the old deadline "
            "(a threat seen again at t+500 holds the block to t+1400)",
            abs(again.expires_at - (t0 + 500 + 900)) < 0.001)
    c.check("no longer due at the ORIGINAL deadline -- this is what keeps a "
            "genuinely malicious domain blocked for as long as it keeps acting",
            not again.is_due(t0 + 901))

    c.check("renew() on an unknown target returns None (caller grants instead)",
            r.renew("block_domain", "never-seen.example") is None)

    # ---------------------------------------------------------------- [4] --
    print("\n[4] FAIL-SAFE: leases survive a restart, and anything that expired "
          "while the engine was down is immediately due")
    r.grant("isolate_host", "this-host", ttl_s=60.0, now=t0)
    reborn = L.LeaseRegistry(path=store)
    c.check("a fresh registry reloads both leases from disk", len(reborn) == 2)
    stranded = reborn.due(now=t0 + 10_000)
    c.check("a lease whose deadline passed during downtime is due on reload -- "
            "without this, a crash would silently make a temporary block "
            "permanent, which is the exact outcome leases exist to prevent",
            len(stranded) == 2)
    c.check("the reloaded lease still carries its dispatchable inverse",
            all(s.reverse_action for s in stranded))

    # ---------------------------------------------------------------- [5] --
    print("\n[5] a corrupt or backward-jumping clock cannot create an immortal block")
    far = r.grant("block_domain", "clockskew.example",
                  ttl_s=900.0, now=t0 + 10 * L.MAX_TTL_S)
    c.check("an expiry further out than MAX_TTL_S reads as DUE, not as a "
            "long block -- 'I cannot tell when this expires' must resolve to "
            "'revert it now'", far.is_due(t0))

    for bad in (0.0, -1.0, L.MAX_TTL_S + 1):
        try:
            r.grant("block_domain", f"bad{bad}.example", ttl_s=bad)
            c.check(f"ttl_s={bad} REFUSED", False)
        except L.LeaseError:
            c.check(f"ttl_s={bad} REFUSED", True)

    # ---------------------------------------------------------------- [6] --
    print("\n[6] release() drops a lease once its reverse action really ran")
    before = len(r)
    c.check("release() returns True for a held lease", r.release(lease.lease_id))
    c.check("count drops by one", len(r) == before - 1)
    c.check("release() of an unknown id returns False", not r.release("deadbeef"))

    # ---------------------------------------------------------------- [7] --
    print("\n[7] registry invariant: an irreversible action may never name an inverse")
    try:
        reversibility.Reversibility(
            action="bogus", reversible=False, rollback="none",
            residual_on_crash="", false_positive_impact="",
            min_severity="critical", reverse_action="un_bogus")
        c.check("reversible=False + reverse_action is REJECTED at construction", False)
    except ValueError:
        c.check("reversible=False + reverse_action is REJECTED at construction", True)

    # cleanup
    try:
        for p in td.iterdir():
            p.unlink()
        td.rmdir()
    except OSError:
        pass

    return c.finish()


def LeaseRegistryOrSkip(L, store):
    try:
        return L.LeaseRegistry(path=store)
    except Exception as exc:   # pragma: no cover
        print(f"  [!] could not construct LeaseRegistry: {exc}")
        return None


if __name__ == "__main__":
    raise SystemExit(main())
