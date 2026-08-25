#!/usr/bin/env python3
"""Run the test suite without changing the machine it runs on.

WHY THIS EXISTS
---------------
Four tests in this directory install real Windows Firewall rules, rebind DNS, or
change adapter state (see HOST_AFFECTING.md). One of them once stranded the
developer's WiFi mid-session. The standing rule was "do not run the full suite
on the live machine", and on 25 Aug 2026 it was run anyway - the network
survived by luck, and 945 accumulated Valkyrie_DoH_* firewall rules turned up
afterwards.

A rule that lives only in someone's memory is not a control. This is the control:
the dangerous tests are excluded by default, and including them requires
deliberately declaring the host disposable.

    python tests/run_safe.py                 # safe subset (default)
    python tests/run_safe.py --all           # refuses unless the env var is set
    VALKYRIE_DISPOSABLE_HOST=1 python tests/run_safe.py --all      # CI / throwaway VM

Exit codes: 0 all passed, 1 something failed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Tests that MUTATE THE HOST. Excluded unless the host is declared disposable.
HOST_AFFECTING = {
    "test_firewall.py",   # installs real Windows Firewall rules
    "test_dns.py",        # binds / redirects DNS
    "test_resolver.py",   # changes resolver configuration
    "test_mac.py",        # touches network adapter state
}

EXIT_SKIP = 77


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--all", action="store_true",
                    help="include host-affecting tests (requires "
                         "VALKYRIE_DISPOSABLE_HOST=1)")
    ap.add_argument("-k", metavar="SUBSTR", default="",
                    help="only run tests whose filename contains SUBSTR")
    args = ap.parse_args()

    include_dangerous = False
    if args.all:
        if os.environ.get("VALKYRIE_DISPOSABLE_HOST") == "1":
            include_dangerous = True
        else:
            print("REFUSED: --all runs tests that install real firewall rules "
                  "and rebind DNS.\n"
                  "         Set VALKYRIE_DISPOSABLE_HOST=1 to confirm this "
                  "machine is throwaway.\n"
                  "         See tests/HOST_AFFECTING.md.")
            return 1

    files = sorted(p.name for p in HERE.glob("test_*.py"))
    if args.k:
        files = [f for f in files if args.k in f]
    skipped_dangerous = []
    if not include_dangerous:
        skipped_dangerous = [f for f in files if f in HOST_AFFECTING]
        files = [f for f in files if f not in HOST_AFFECTING]

    print(f"running {len(files)} test files"
          + (f"  (excluding {len(skipped_dangerous)} host-affecting)"
             if skipped_dangerous else "  INCLUDING HOST-AFFECTING TESTS"))
    print("=" * 74)

    passed, failed, skipped = [], [], []
    t0 = time.time()
    for name in files:
        r = subprocess.run([sys.executable, str(HERE / name)],
                           capture_output=True, text=True,
                           env={**os.environ, "PYTHONUTF8": "1"})
        if r.returncode == 0:
            passed.append(name)
        elif r.returncode == EXIT_SKIP:
            skipped.append(name)
        else:
            failed.append((name, r.returncode, (r.stdout or "")[-1400:]))
            print(f"  FAIL  {name}  (exit {r.returncode})")

    dur = time.time() - t0
    print("=" * 74)
    print(f"passed {len(passed)}   failed {len(failed)}   skipped {len(skipped)}"
          f"   in {dur:.0f}s")
    if skipped_dangerous:
        print(f"\nNOT RUN (host-affecting, see HOST_AFFECTING.md): "
              f"{', '.join(skipped_dangerous)}")

    if failed:
        print("\nFAILURES")
        for name, code, tail in failed:
            print(f"\n--- {name} (exit {code}) " + "-" * (46 - len(name)))
            for line in tail.splitlines():
                if any(m in line for m in ("FAIL", "Error", "error:",
                                           "Traceback", "VALKYRIE-RESULT")):
                    print("   " + line.strip())
        return 1

    print("\nALL PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
