"""Tests for valkyrie/fingerprint.py

SAFETY: never calls normalize()/restore() for real when running as admin, since
that would change this machine's global TCP/IP settings. Only the read-only
status() path and the admin gate (which short-circuits before any change) are
exercised live; backup persistence is tested against a temp file.

Usage: python test_fingerprint.py
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from valkyrie.fingerprint import NetworkFingerprint, _is_windows, _is_admin

PASS = 0
FAIL = 0

def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  + [PASS]  {label}")
    else:
        FAIL += 1; print(f"  X [FAIL]  {label}" + (f"  ({detail})" if detail else ""))

print("Valkyrie network fingerprint tests")
print("=" * 50)

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
    backup_path = Path(tf.name)
backup_path.unlink(missing_ok=True)

fp = NetworkFingerprint(backup_path=backup_path)

# ── status() is read-only and well-formed ────────────────────────────────────
print("\n-- status --------------------------------------------")
st = fp.status()
check("status() returns a dict", isinstance(st, dict))
for k in ("supported", "ttl", "ttl_normalized", "tcp_timestamps",
          "timestamps_normalized", "normalized", "backup_present"):
    check(f"status has key '{k}'", k in st)
check("supported matches platform", st["supported"] == _is_windows())
check("backup_present is False initially", st["backup_present"] is False)

# ── Backup persistence round-trip ────────────────────────────────────────────
print("\n-- backup persistence --------------------------------")
fp._save_backup({"DefaultTTL": 128, "tcp_timestamps": True})
loaded = fp._load_backup()
check("backup round-trips", loaded == {"DefaultTTL": 128, "tcp_timestamps": True}, str(loaded))
check("backup_present now True", fp.status()["backup_present"] is True)
fp._clear_backup()
check("backup cleared", fp._load_backup() is None)

# ── restore() with no backup ─────────────────────────────────────────────────
print("\n-- restore with no backup ----------------------------")
if not _is_windows():
    ok = fp.restore()
    check("non-Windows restore() returns False with message",
          ok is False and "Windows-only" in fp.last_error, fp.last_error)
elif not _is_admin():
    ok = fp.restore()
    check("non-admin restore() returns False with admin message",
          ok is False and "Administrator" in fp.last_error, fp.last_error)
else:
    # admin: restore with no backup should fail cleanly (no system change)
    ok = fp.restore()
    check("admin restore() with no backup fails cleanly",
          ok is False and "no fingerprint backup" in fp.last_error, fp.last_error)

# ── normalize() admin gate (safe — non-admin path only) ──────────────────────
print("\n-- normalize admin gate ------------------------------")
if not _is_windows():
    ok = fp.normalize()
    check("non-Windows normalize() returns False", ok is False and bool(fp.last_error))
elif not _is_admin():
    ok = fp.normalize()
    check("non-admin normalize() returns admin error, no change",
          ok is False and "Administrator" in fp.last_error, fp.last_error)
else:
    print("  ~ [SKIP]  running as admin — not exercising live normalize() "
          "(would change global TCP/IP settings)")

backup_path.unlink(missing_ok=True)

print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
sys.exit(1 if FAIL else 0)
