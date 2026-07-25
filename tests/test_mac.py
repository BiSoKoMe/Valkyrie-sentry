"""Tests for valkyrie/mac_randomizer.py

Verifies MAC generation correctness without touching real network interfaces.
Usage: python test_mac.py
"""

import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.mac_randomizer import (
    _generate_mac, _is_valid_mac, MacRandomizer,
    generate_mac, mac_for_network, is_unicast, is_locally_administered,
)
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

# ── Test 2: Default style is spec-compliant locally-administered ──────────────
# The default (no vendor blend) must be a proper LA random address: LA bit SET,
# multicast bit CLEAR, on the FIRST octet — the iOS/Android style. It must NOT
# carry a real vendor OUI (a vendor OUI + LA bit is a combination real hardware
# never has, so it would itself be a fingerprint).
print("\n-- Default style: locally-administered random --------")
oui_set = set(o.upper() for o in REALISTIC_OUIS)
oui_prefixes = set((o.split(":")[1], o.split(":")[2]) for o in oui_set)
la_errors = []
vendor_leak = 0
for _ in range(50):
    mac  = generate_mac()          # default: vendor_blend=False
    if not (is_locally_administered(mac) and is_unicast(mac)):
        la_errors.append(mac)
    p = mac.upper().split(":")
    if (p[1], p[2]) in oui_prefixes:
        vendor_leak += 1           # coincidental collisions possible but rare
check("50 default MACs are locally-administered + unicast",
      len(la_errors) == 0, str(la_errors[:2]))
check("default MACs do not systematically wear a real vendor OUI",
      vendor_leak <= 2, f"vendor-looking: {vendor_leak}/50")

# ── Test 3: Vendor-blend mode — real OUI, LA bit CLEAR ────────────────────────
print("\n-- Vendor-blend style: real OUI, universally-admin ---")
blend_bad = []
for _ in range(50):
    mac = generate_mac(vendor_blend=True)
    p = mac.upper().split(":")
    oui_match = (p[1], p[2]) in oui_prefixes
    # Blend mode impersonates a real vendor → LA bit must be CLEAR (UAA),
    # multicast clear (unicast).
    if not (oui_match and (not is_locally_administered(mac)) and is_unicast(mac)):
        blend_bad.append(mac)
check("50 vendor-blend MACs use a real OUI with LA bit clear + unicast",
      len(blend_bad) == 0, str(blend_bad[:2]))

# ── Test 2b: CSPRNG — no repeats, high entropy across many draws ──────────────
print("\n-- CSPRNG uniqueness ---------------------------------")
draws = [generate_mac() for _ in range(2000)]
check("2000 CSPRNG MACs are (essentially) all unique",
      len(set(draws)) >= 1999, f"unique={len(set(draws))}/2000")
check("all generated MACs pass strict format validation",
      all(_is_valid_mac(m) for m in draws))

# ── Test 2c: Per-network derivation — stable, unlinkable, key-dependent ───────
print("\n-- Per-network stable address (iOS/Android model) ----")
key_a = b"\x11" * 32
key_b = b"\x22" * 32
mac_home_1 = mac_for_network(key_a, "ssid:HomeWiFi")
mac_home_2 = mac_for_network(key_a, "ssid:HomeWiFi")
mac_cafe   = mac_for_network(key_a, "ssid:CoffeeShop")
mac_home_kb = mac_for_network(key_b, "ssid:HomeWiFi")
check("same key + same network → identical address (stable)",
      mac_home_1 == mac_home_2, f"{mac_home_1} vs {mac_home_2}")
check("same key + different network → different address (unlinkable)",
      mac_home_1 != mac_cafe, f"{mac_home_1} == {mac_cafe}")
check("different key + same network → different address (needs the secret)",
      mac_home_1 != mac_home_kb, f"{mac_home_1} == {mac_home_kb}")
check("derived address is valid + locally-administered + unicast",
      _is_valid_mac(mac_home_1) and is_locally_administered(mac_home_1)
      and is_unicast(mac_home_1), mac_home_1)
# Derivation must not be a trivial function of the network id an observer sees.
check("derived address is not a visible slice of the network id",
      "484f6d65" not in mac_home_1.replace(":", "").lower())

# ── Test 2d: Backward-compat _generate_mac still returns a valid address ──────
print("\n-- Backward-compat _generate_mac ---------------------")
check("_generate_mac() still yields a valid unicast MAC",
      _is_valid_mac(_generate_mac()) and is_unicast(_generate_mac()))

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
