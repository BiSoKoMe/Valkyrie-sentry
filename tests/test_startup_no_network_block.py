#!/usr/bin/env python3
"""Protection must never wait on the network to start.

WHY THIS EXISTS (the regression it pins)
----------------------------------------
Enabling threat-feed downloads by default (USE_EXTERNAL_LISTS = True) is the
right call for detection value - feeds that never run protect nobody. But the
first implementation left the fetch on the SYNCHRONOUS startup path, so the
engine blocked on a ~500,000-domain download before it protected anything:

  * minutes of dead startup on a slow link, indistinguishable from a hang;
  * up to 30s PER FEED of urllib timeout on an offline machine - and
    offline/air-gapped is a target environment for this product, not an
    edge case;
  * `test_startup_smoke` went from 9/9 passing to timing out.

The rule this file enforces: **startup loads seed + cache only (both offline,
both instant); every network refresh happens on a background thread and
hot-swaps under the lock the DNS path already reads through.**

  [1] BlocklistManager.load() does not download unless explicitly told to
  [2] A background refresh exists, is a daemon, and swaps atomically
  [3] ThreatIntelManager.load() defaults to cache-only
  [4] The intel daemon's FIRST refresh is soon, not one full 6h interval away
  [5] __main__ wires both cache-only, with --update as the sole exception
"""

from __future__ import annotations

import re
import sys
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    print("\n=== startup must not block on the network ===\n")

    import valkyrie.blocklist as bl
    import valkyrie.threat_intel as ti

    print("[1] BlocklistManager.load() does not download when told not to")
    downloads = {"n": 0}
    real_update = bl.update_blocklist
    bl.update_blocklist = lambda console=None: downloads.__setitem__("n", downloads["n"] + 1)
    try:
        m = bl.BlocklistManager()
        m.load(allow_download=False)
        _check("allow_download=False performs zero downloads", downloads["n"] == 0)
        _check("seed domains still loaded offline", m.is_blocked("doubleclick.net")
               or len(getattr(m, "_exact", ())) > 0)
    finally:
        bl.update_blocklist = real_update

    print("\n[2] Background refresh exists, is a daemon, swaps atomically")
    _check("start_background_refresh() exists",
           hasattr(bl.BlocklistManager, "start_background_refresh"))
    src = (_ROOT / "valkyrie" / "blocklist.py").read_text(encoding="utf-8")
    _check("refresh thread is a daemon (cannot block shutdown)",
           re.search(r"start_background_refresh.*?daemon=True", src, re.S) is not None)
    _check("refresh reloads through _read_from_disk (atomic swap under lock)",
           re.search(r"start_background_refresh.*?_read_from_disk", src, re.S) is not None)
    _check("refresh swallows its own errors (never affects a running engine)",
           re.search(r"start_background_refresh.*?except Exception", src, re.S) is not None)

    print("\n[3] ThreatIntelManager.load() is cache-only when told")
    fetches = {"n": 0}
    mgr = ti.ThreatIntelManager(feeds=[], cache_dir=_ROOT / "does_not_exist")
    mgr.refresh = lambda *a, **k: fetches.__setitem__("n", fetches["n"] + 1)
    mgr.load(allow_download=False)
    _check("allow_download=False performs zero feed fetches", fetches["n"] == 0)

    print("\n[4] The intel daemon refreshes SOON, not one full interval later")
    delay = getattr(ti.ThreatIntelManager, "_INITIAL_REFRESH_DELAY", None)
    _check("an initial-refresh delay is defined", delay is not None)
    if delay is not None:
        _check(f"initial delay is short ({delay}s <= 120s) — a box offline for "
               f"weeks gets IOCs in a minute, not 6 hours", delay <= 120)
        _check(f"initial delay is not zero ({delay}s) — startup finishes first",
               delay > 0)
    _check("the daemon thread is a daemon",
           'daemon=True' in (_ROOT / "valkyrie" / "threat_intel.py").read_text(encoding="utf-8"))

    print("\n[5] __main__ wires both cache-only, --update the sole exception")
    mainsrc = (_ROOT / "valkyrie" / "__main__.py").read_text(encoding="utf-8")
    _check("blocklist.load is gated on args.update, not on _dl",
           re.search(r"blocklist\.load\([^)]*allow_download\s*=\s*True if args\.update else False",
                     mainsrc, re.S) is not None)
    _check("threat_intel.load is gated on args.update, not on _dl",
           re.search(r"threat_intel\.load\([^)]*allow_download\s*=\s*True if args\.update else False",
                     mainsrc, re.S) is not None)
    _check("background blocklist refresh is started at startup",
           "start_background_refresh(" in mainsrc)

    print("\n" + "=" * 58)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED — startup is offline-safe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
