"""Tests for valkyrie/mac_randomizer.py

Verifies MAC generation correctness without touching real network interfaces.
Usage: python test_mac.py
"""

import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.mac_randomizer import _generate_mac, _is_valid_mac, MacRandomizer
from valkyrie.config import REALISTIC_OUIS, MAC_NEVER_RANDOMIZE

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

print("Valkyrie MAC randomizer test")
print("=" * 50)

# ── Test 1: Valid MAC format ──────────────────────────────────────────────────
print("\n-- MAC format ----------------------------------------")
for _ in range(20):
    mac = _generate_mac()
    if not _is_valid_mac(mac):
        check("Generated MAC is valid format", False, f"got: {mac}")
        break
else:
    check("20 generated MACs all pass format check (XX:XX:XX:XX:XX:XX)", True)

# ── Test 2: OUI from known list ───────────────────────────────────────────────
print("\n-- OUI source ----------------------------------------")
oui_set = set(o.upper() for o in REALISTIC_OUIS)
oui_errors = []
for _ in range(50):
    mac = _generate_mac()
    oui = ":".join(mac.split(":")[:3]).upper()
    # The OUI first byte may differ due to LA-bit manipulation; check original OUI list
    # Re-derive: the first byte is modified, so check only bytes 1-2 match any known OUI bytes 1-2
    found = False
    mac_parts = mac.upper().split(":")
    for known_oui in oui_set:
        known_parts = known_oui.split(":")
        if mac_parts[1] == known_parts[1] and mac_parts[2] == known_parts[2]:
            found = True
            break
    if not found:
        oui_errors.append(mac)

check(f"50 MACs have OUI bytes 1-2 matching known vendors", len(oui_errors) == 0,
      f"mismatches: {oui_errors[:3]}")

# ── Test 3: Locally administered bit ─────────────────────────────────────────
print("\n-- Locally administered bit --------------------------")
la_errors = []
for _ in range(50):
    mac  = _generate_mac()
    byte = int(mac.split(":")[0], 16)
    la   = (byte >> 1) & 1         # bit 1 = locally administered
    mc   = byte & 1                # bit 0 = multicast
    if la != 1 or mc != 0:
        la_errors.append((mac, f"byte0=0x{byte:02X} la={la} mc={mc}"))

check("50 MACs have locally administered bit set, multicast bit clear",
      len(la_errors) == 0, str(la_errors[:2]) if la_errors else "")

# ── Test 4: Backup/restore roundtrip ─────────────────────────────────────────
print("\n-- Backup / restore ----------------------------------")
import tempfile, json
from pathlib import Path

# Patch MAC_BACKUP_PATH to a temp file so we don't touch real storage
import valkyrie.config as _cfg
orig_backup = _cfg.MAC_BACKUP_PATH
with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
    tmp_backup = Path(tf.name)

_cfg.MAC_BACKUP_PATH = tmp_backup

try:
    mac_inst = MacRandomizer(store=None)
    # Simulate saving a backup
    test_backup = {"eth0": "AA:BB:CC:DD:EE:FF"}
    mac_inst._save_backup(test_backup)
    loaded = mac_inst._load_backup()
    check("Backup written and loaded correctly",
          loaded == test_backup, str(loaded))
    check("get_original returns backed-up value",
          mac_inst.get_original("eth0") == "AA:BB:CC:DD:EE:FF",
          mac_inst.get_original("eth0"))
    check("get_original returns empty for unknown iface",
          mac_inst.get_original("wlan99") == "", mac_inst.get_original("wlan99"))
finally:
    _cfg.MAC_BACKUP_PATH = orig_backup
    tmp_backup.unlink(missing_ok=True)

# ── Test 5: Never-randomise list respected ────────────────────────────────────
print("\n-- Never-randomise list ------------------------------")
mac_inst2 = MacRandomizer(store=None)
for iface in MAC_NEVER_RANDOMIZE:
    result = mac_inst2._resolve_interfaces(iface)
    check(f"Interface '{iface}' excluded by MAC_NEVER_RANDOMIZE", result == [], str(result))

# ── Test 6: Status dict structure ─────────────────────────────────────────────
print("\n-- Status dict ---------------------------------------")
st = MacRandomizer(store=None).status()
check("status() returns a dict", isinstance(st, dict))

# ── Test 7: _apply_windows apply/cycle path (mocked — no real hardware) ───────
# This is the exact path MAC_DIAGNOSIS_REPORT.md found silently broken (netsh
# failures/timeouts were swallowed, live-mismatch was never checked). None of
# tests 1-6 exercise it at all. These mock subprocess.run, winreg (via
# sys.modules — safe on any OS, the real registry is never touched) and
# time.sleep (so timeout-path tests don't actually wait), and call
# _apply_windows directly so no admin rights or real adapter are needed.
print("\n-- Windows apply/cycle path (mocked, no real hardware) --")
import subprocess as _subprocess
from unittest.mock import MagicMock, patch

_fake_winreg = MagicMock()
_fake_winreg.HKEY_LOCAL_MACHINE = "HKLM"
_fake_winreg.KEY_SET_VALUE = 0x2
_fake_winreg.REG_SZ = 1
_fake_winreg.OpenKey.return_value.__enter__ = MagicMock(return_value=MagicMock())
_fake_winreg.OpenKey.return_value.__exit__  = MagicMock(return_value=False)


def _run_apply_windows(run_side_effect, readback_mac="AA:BB:CC:DD:EE:FF"):
    """Call the real _apply_windows with subprocess/winreg/sleep mocked out.

    Returns (result, last_error, run_call_count).
    """
    inst = MacRandomizer(store=None)
    with patch.dict(sys.modules, {"winreg": _fake_winreg}), \
         patch.object(inst, "_find_windows_adapter_key", return_value=r"FAKE\PATH"), \
         patch.object(inst, "_read_current_mac", return_value=readback_mac), \
         patch("valkyrie.mac_randomizer.time.sleep", return_value=None), \
         patch("valkyrie.mac_randomizer.subprocess.run", side_effect=run_side_effect) as mock_run:
        result = inst._apply_windows("Wi-Fi", "AA:BB:CC:DD:EE:FF")
        return result, inst.last_error, mock_run.call_count


def _ok(returncode=0):
    return MagicMock(returncode=returncode, stdout="", stderr="")


# 7a. netsh disable fails (nonzero return) -> False, no retry beyond disable
result, err, calls = _run_apply_windows([_ok(1)])
check("disable failure returns False", result is False)
check("disable failure sets a 'disable failed' last_error", "disable failed" in err, err)
check("disable failure makes exactly 1 netsh call (no enable attempt)", calls == 1, str(calls))

# 7b. netsh disable succeeds, enable fails (nonzero return) -> False
result, err, calls = _run_apply_windows([_ok(0), _ok(1)])
check("enable failure returns False", result is False)
check("enable failure sets an 'enable failed' last_error", "enable failed" in err, err)

# 7c. netsh disable times out -> False, best-effort re-enable attempted (2 calls total)
result, err, calls = _run_apply_windows([_subprocess.TimeoutExpired(cmd="netsh", timeout=15)])
check("disable timeout returns False", result is False)
check("disable timeout sets a timeout last_error", "disable timed out" in err, err)
check("disable timeout attempts a best-effort re-enable (2 netsh calls)", calls == 2, str(calls))

# 7d. netsh enable times out -> False
result, err, calls = _run_apply_windows(
    [_ok(0), _subprocess.TimeoutExpired(cmd="netsh", timeout=15)]
)
check("enable timeout returns False", result is False)
check("enable timeout sets a timeout last_error", "enable timed out" in err, err)

# 7e. both netsh calls succeed, but live MAC readback does NOT match what was
# written — this is the exact silent-failure class MAC_DIAGNOSIS_REPORT.md
# found: registry write succeeds, cycle "succeeds", but the adapter never
# actually picked up the new address.
result, err, calls = _run_apply_windows([_ok(0), _ok(0)], readback_mac="11:22:33:44:55:66")
check("live-readback mismatch returns False (not a silent success)", result is False)
check("live-readback mismatch sets a 'did not apply' last_error",
      "did not apply" in err, err)

# 7f. Happy path — both netsh calls succeed and live readback matches
result, err, calls = _run_apply_windows([_ok(0), _ok(0)], readback_mac="AA:BB:CC:DD:EE:FF")
check("full success path (netsh OK + readback matches) returns True", result is True)

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
if FAIL:
    print("  RESULT: SOME TESTS FAILED")
    sys.exit(1)
else:
    print("  RESULT: ALL TESTS PASSED")
    sys.exit(0)
