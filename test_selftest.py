"""Tests for valkyrie/self_test.py - preflight checks + heartbeat.

Usage: python test_selftest.py
"""

import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from valkyrie.self_test import (
    Check, preflight, critical_failures, HeartbeatMonitor, _probe_dns,
)

PASS = 0
FAIL = 0

def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  + [PASS]  {label}")
    else:
        FAIL += 1; print(f"  X [FAIL]  {label}" + (f"  ({detail})" if detail else ""))

print("Valkyrie self-test / heartbeat tests")
print("=" * 50)

# --- Preflight ---
print("\n-- preflight -----------------------------------------")
checks = preflight(port=5300, want_dns=True, want_unbound=False, want_tls=False)
check("preflight returns a non-empty list", isinstance(checks, list) and len(checks) > 0)
check("every item is a Check", all(isinstance(c, Check) for c in checks))

names = {c.name for c in checks}
check("includes a Dependencies check", any("Dependenc" in n for n in names))
check("includes a Data directory check", any("Data" in n for n in names))

deps = next(c for c in checks if "Dependenc" in c.name)
check("Dependencies check is marked critical", deps.critical is True)
check("Dependencies pass in this environment", deps.ok, deps.detail)

# want_tls adds a TLS CA check; want_unbound=False omits the Unbound check
tls_checks = preflight(port=5300, want_dns=True, want_unbound=True, want_tls=True)
check("want_unbound=True adds an Unbound check", any("Unbound" in c.name for c in tls_checks))
check("want_tls=True adds a TLS CA check", any("TLS" in c.name for c in tls_checks))

# critical_failures only returns failed critical checks
synthetic = [
    Check("ok-crit", True, "", critical=True),
    Check("bad-crit", False, "boom", critical=True),
    Check("bad-advisory", False, "meh", critical=False),
]
cf = critical_failures(synthetic)
check("critical_failures returns only failed critical checks",
      [c.name for c in cf] == ["bad-crit"], str([c.name for c in cf]))

# --- _probe_dns against a closed port ---
print("\n-- probe ---------------------------------------------")
check("_probe_dns returns False on a dead port", _probe_dns("127.0.0.1", 59991, timeout=0.5) is False)

# --- _probe_dns against a fake responder ---
def _fake_dns_server(port, stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.3)
    while not stop.is_set():
        try:
            data, addr = s.recvfrom(4096)
            # Echo back a 12+ byte "response"
            s.sendto(data + b"\x00" * 4, addr)
        except socket.timeout:
            continue
        except OSError:
            break
    s.close()

stop = threading.Event()
port = 53535
t = threading.Thread(target=_fake_dns_server, args=(port, stop), daemon=True)
t.start()
time.sleep(0.2)
check("_probe_dns returns True when something answers", _probe_dns("127.0.0.1", port, timeout=1.0))

# --- HeartbeatMonitor debounce ---
print("\n-- heartbeat -----------------------------------------")
hb = HeartbeatMonitor("127.0.0.1", port, interval=999)
check("monitor healthy against live responder", hb.check_once() is True)

stop.set(); time.sleep(0.4)   # kill the responder
hb2 = HeartbeatMonitor("127.0.0.1", 59992, interval=999)
first = hb2.check_once()
second = hb2.check_once()
check("one failure does NOT flip healthy (debounce)", first is True, f"first={first}")
check("two consecutive failures flip to unhealthy", second is False and hb2.is_healthy() is False)

st = hb2.status()
check("status() has expected keys",
      all(k in st for k in ("healthy", "last_ok", "last_check", "fail_count", "dns_port")))

# --- Summary ---
print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
sys.exit(1 if FAIL else 0)
