"""Tests for valkyrie/zero_log.py

Verifies RAM-only mode, no disk writes, secure wipe, and tamper detection.
Usage: python test_zero_log.py
"""

import sys
import time
import tempfile
import sqlite3
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

PASS = 0
FAIL = 0

def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  + [PASS]  {label}")
    else:
        FAIL += 1
        print(f"  X [FAIL]  {label}" + (f"  ({detail})" if detail else ""))

print("Valkyrie zero-log mode test")
print("=" * 50)

from valkyrie.config import RAM_DB_URI
from valkyrie.zero_log import ZeroLogMode
from valkyrie.store import Store, DnsEvent

# ── Test 1: RAM DB creates with shared cache URI ──────────────────────────────
print("\n-- RAM database ------------------------------------------")
try:
    conn = sqlite3.connect(RAM_DB_URI, uri=True, check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS test_tbl (id INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO test_tbl VALUES (1)")
    conn.commit()
    row = conn.execute("SELECT COUNT(*) FROM test_tbl").fetchone()
    conn.close()
    check("RAM DB creates and accepts writes", row[0] == 1)
except Exception as e:
    check("RAM DB creates and accepts writes", False, str(e))

# ── Test 2: make_ram_store() returns a functioning Store ─────────────────────
print("\n-- RAM store -----------------------------------------")
zl = ZeroLogMode()
zl.enable()
try:
    ram_store = zl.make_ram_store()
    ram_store.start()

    check("make_ram_store() returns Store instance", isinstance(ram_store, Store))
    check("RAM store reports is_ram_mode() = True", ram_store.is_ram_mode())

    # Write an event
    event = DnsEvent.now(
        domain="test.example.com", decision="blocked",
        process_name="test", process_pid=0, process_path="",
        reason="unit test", raw_category="test",
    )
    ram_store.log(event)
    time.sleep(0.3)   # let writer thread flush

    stats = ram_store.stats()
    check("Events written to RAM store are readable",
          stats["total_24h"] >= 1, str(stats))

    ram_store.stop()
except Exception as e:
    check("RAM store operations work", False, str(e))

# ── Test 3: Disk DB unchanged when RAM mode active ────────────────────────────
print("\n-- Disk isolation ------------------------------------")
with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
    disk_path = Path(tf.name)

disk_store = Store(db_path=disk_path)
disk_store.start()
disk_store.stop()
size_before = disk_path.stat().st_size

# Create a second RAM store and write to it — disk must not change
zl2 = ZeroLogMode()
zl2.enable()
ram2 = zl2.make_ram_store()
ram2.start()
for i in range(5):
    ram2.log(DnsEvent.now(
        domain=f"noise{i}.com", decision="allowed",
        process_name="test", process_pid=0, process_path="", reason="",
    ))
time.sleep(0.3)
ram2.stop()

size_after = disk_path.stat().st_size
check("Disk DB size unchanged while RAM store wrote 5 events",
      size_before == size_after,
      f"before={size_before} after={size_after}")
try:
    disk_path.unlink(missing_ok=True)
except PermissionError:
    pass   # Windows: SQLite WAL file may linger briefly

# ── Test 4: Secure wipe runs on disable() ────────────────────────────────────
print("\n-- Secure wipe ---------------------------------------")
zl3 = ZeroLogMode()
zl3.enable()
r3  = zl3.make_ram_store()
r3.start()
r3.log(DnsEvent.now(
    domain="wipe.test", decision="allowed",
    process_name="test", process_pid=0, process_path="", reason="",
))
time.sleep(0.3)
try:
    zl3.disable()   # should print "Zero log: all session data wiped"
    check("disable() / secure wipe runs without error", True)
except Exception as e:
    check("disable() / secure wipe runs without error", False, str(e))

# ── Test 5: Tamper detection detects file modification ────────────────────────
print("\n-- Tamper detection ----------------------------------")
import hashlib
from valkyrie.zero_log import _PKG_DIR

zl4 = ZeroLogMode()
zl4.enable()

# Manually corrupt one hash in the baseline to simulate a changed file
py_files = sorted(_PKG_DIR.glob("*.py"))
if py_files:
    target = str(py_files[0])
    zl4._hashes[target] = "0" * 64   # wrong hash

    tampered = []
    zl4.on_tamper(lambda files: tampered.extend(files))
    zl4._check_integrity()

    check("Tamper detection fires when hash mismatches",
          len(tampered) > 0, f"tampered={tampered}")
    check("Tampered file is the one we modified",
          target in tampered, f"expected {target} in {tampered}")
else:
    check("Tamper detection: no .py files found to test", False, "no .py files?")

zl4._stop_event.set()

# ── Test 6: status() returns correct mode ────────────────────────────────────
print("\n-- Status dict ---------------------------------------")
zl5 = ZeroLogMode()
st_off = zl5.status()
check("status() active=False when not enabled", st_off["active"] is False)
check("status() mode='disk' when not enabled", st_off["mode"] == "disk")
check("status() disk_writes='enabled' when not enabled", st_off["disk_writes"] == "enabled")

zl5.enable()
st_on = zl5.status()
check("status() active=True when enabled", st_on["active"] is True)
check("status() mode contains 'ram' when enabled", "ram" in st_on["mode"])
check("status() disk_writes='none' when enabled", st_on["disk_writes"] == "none")
zl5._stop_event.set()

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
if FAIL:
    print("  RESULT: SOME TESTS FAILED")
    sys.exit(1)
else:
    print("  RESULT: ALL TESTS PASSED")
    sys.exit(0)
