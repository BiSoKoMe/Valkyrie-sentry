"""Tests for valkyrie/meeting_mode.py

SAFETY: these tests never actually activate Meeting Mode when running with
Administrator rights, because that would genuinely cut this machine off the
internet. The live activate() path is only exercised in states where it is
guaranteed to short-circuit before touching the firewall (non-Windows, or
Windows without admin).

Usage: python test_meeting.py
"""

import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from valkyrie.meeting_mode import MeetingMode, _is_windows, _is_admin

PASS = 0
FAIL = 0

def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  + [PASS]  {label}")
    else:
        FAIL += 1; print(f"  X [FAIL]  {label}" + (f"  ({detail})" if detail else ""))

print("Valkyrie Meeting Mode tests")
print("=" * 50)

# temp state file so we never touch real state
with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
    state_path = Path(tf.name)
state_path.unlink(missing_ok=True)

mm = MeetingMode(state_path=state_path)

# ── Inactive status ──────────────────────────────────────────────────────────
print("\n-- inactive status -----------------------------------")
st = mm.status()
check("status() returns a dict", isinstance(st, dict))
check("inactive: active is False", st["active"] is False)
check("inactive: duration_minutes is 0", st["duration_minutes"] == 0)
check("inactive: activated_at is None", st["activated_at"] is None)

# ── Duration computed from persisted state ───────────────────────────────────
print("\n-- duration from state -------------------------------")
started = (datetime.now(timezone.utc) - timedelta(minutes=7)).isoformat(timespec="seconds")
state_path.write_text(json.dumps({
    "active": True, "activated_at": started, "restore_policy": "blockinbound,allowoutbound",
}), encoding="utf-8")
st2 = mm.status()
check("active state reads back as active", st2["active"] is True)
check("duration_minutes ~= 7", st2["duration_minutes"] in (6, 7, 8), str(st2["duration_minutes"]))

# ── Malformed state degrades gracefully ──────────────────────────────────────
print("\n-- malformed state -----------------------------------")
state_path.write_text("{ not json", encoding="utf-8")
st3 = mm.status()
check("malformed state -> inactive, no crash", st3["active"] is False)
state_path.unlink(missing_ok=True)

# ── Admin gate (safe — only runs live path when it cannot touch firewall) ────
print("\n-- admin gate ----------------------------------------")
if not _is_windows():
    res = mm.activate()
    check("non-Windows activate() returns error", bool(res.get("error")), str(res))
elif not _is_admin():
    res = mm.activate()
    check("non-admin activate() returns admin error, no firewall change",
          "Administrator" in (res.get("error") or ""), str(res))
    check("non-admin activate() did not mark active", res.get("active") is False)
else:
    print("  ~ [SKIP]  running as admin — not exercising live activate() "
          "(would block all network traffic)")

state_path.unlink(missing_ok=True)

print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
sys.exit(1 if FAIL else 0)
