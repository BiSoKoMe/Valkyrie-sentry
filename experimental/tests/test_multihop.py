"""Tests for valkyrie/multihop.py

Verifies WireGuard config generation, key format, kill-switch syntax,
and cross-config consistency without network access.
Usage: python test_multihop.py
"""

import sys
import re
import base64
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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

print("Valkyrie multi-hop VPN test")
print("=" * 50)

# Redirect data dir to temp so we don't pollute the real data/
import valkyrie.config as _cfg
_orig_data = _cfg.DATA_DIR
_orig_hop1 = _cfg.WIREGUARD_HOP1_CONF
_orig_hop2 = _cfg.WIREGUARD_HOP2_CONF
with tempfile.TemporaryDirectory() as tmpdir:
    _tmp = Path(tmpdir)
    _cfg.DATA_DIR            = _tmp
    _cfg.WIREGUARD_HOP1_CONF = _tmp / "wg_hop1.conf"
    _cfg.WIREGUARD_HOP2_CONF = _tmp / "wg_hop2.conf"

    from valkyrie.multihop import MultiHopVPN, _make_keypair, _KILL_SWITCH_UP, _KILL_SWITCH_DOWN

    mh = MultiHopVPN()

    # --- Test 1: Configs generate without error ---
    print("\n-- Config generation ---------------------------------")
    try:
        result = mh.generate_config(hop1_ip="1.2.3.4", hop2_ip="5.6.7.8")
        check("generate_config() returns without error", True)
    except Exception as e:
        check("generate_config() returns without error", False, str(e))
        result = {}

    check("hop1 conf file written", _cfg.WIREGUARD_HOP1_CONF.exists())
    check("hop2 conf file written", _cfg.WIREGUARD_HOP2_CONF.exists())

    # --- Test 2: Keypairs are valid WireGuard base64 ---
    print("\n-- Key format ----------------------------------------")
    _B64_RE = re.compile(r'^[A-Za-z0-9+/]{43}=$')

    def is_wg_key(k: str) -> bool:
        try:
            decoded = base64.b64decode(k)
            return len(decoded) == 32 and bool(_B64_RE.match(k))
        except Exception:
            return False

    for _ in range(10):
        priv, pub = _make_keypair()
        if not is_wg_key(priv):
            check("Private key is valid WireGuard base64 (32 bytes)", False, priv)
            break
        if not is_wg_key(pub):
            check("Public key is valid WireGuard base64 (32 bytes)", False, pub)
            break
    else:
        check("10x private keys are valid WireGuard base64", True)
        check("10x public keys are valid WireGuard base64", True)

    check("result contains hop1_priv key", is_wg_key(result.get("hop1_priv", "")))
    check("result contains hop2_priv key", is_wg_key(result.get("hop2_priv", "")))

    # --- Test 3: Kill-switch rules syntactically correct ---
    print("\n-- Kill-switch rules ---------------------------------")
    check("Kill switch PostUp contains iptables OUTPUT",
          "iptables" in _KILL_SWITCH_UP and "OUTPUT" in _KILL_SWITCH_UP,
          _KILL_SWITCH_UP)
    check("Kill switch PreDown is the delete (-D) form",
          "-D OUTPUT" in _KILL_SWITCH_DOWN,
          _KILL_SWITCH_DOWN)

    hop1_text = result.get("hop1_conf", "")
    hop2_text = result.get("hop2_conf", "")
    check("hop1 conf contains PostUp kill-switch", "PostUp" in hop1_text)
    check("hop1 conf contains PreDown kill-switch", "PreDown" in hop1_text)
    check("hop2 conf contains PostUp kill-switch", "PostUp" in hop2_text)
    check("hop2 conf contains PreDown kill-switch", "PreDown" in hop2_text)

    # --- Test 4: Configs reference each other correctly ---
    print("\n-- Cross-config consistency --------------------------")
    check("hop1 conf Endpoint is hop1_ip:51820",
          "1.2.3.4:51820" in hop1_text, hop1_text[:300])
    # hop2's Endpoint MUST be hop2's real public IP (the address the client
    # dials directly), NOT a WireGuard-internal overlay address like
    # 10.13.14.1 - that address doesn't exist on the public internet and
    # can't be used to perform the initial handshake. This used to be
    # hardcoded to 10.13.14.1:51820 and hop2_ip was silently discarded; see
    # docs/VPN_SELFHEAL_AUDIT_REPORT.md.
    check("hop2 conf Endpoint is hop2_ip:51820 (not the internal overlay IP)",
          "5.6.7.8:51820" in hop2_text and "10.13.14.1:51820" not in hop2_text,
          hop2_text[:300])
    check("hop1 conf AllowedIPs routes into hop2 subnet",
          "10.13.14.0/24" in hop1_text)
    check("hop2 conf AllowedIPs is 0.0.0.0/0 (full tunnel)",
          "0.0.0.0/0" in hop2_text)
    check("hop2 conf has PersistentKeepalive",
          "PersistentKeepalive" in hop2_text)
    check("hop1 conf has placeholder for hop1 pubkey",
          "REPLACE_WITH_HOP1_PUBKEY" in hop1_text)
    check("hop2 conf has placeholder for hop2 pubkey",
          "REPLACE_WITH_HOP2_PUBKEY" in hop2_text)

    # --- Test 4b: Invalid hop IPs are rejected, not silently written ---
    print("\n-- Input validation -----------------------------------")
    try:
        mh.generate_config(hop1_ip="1.2.3.4; rm -rf /", hop2_ip="5.6.7.8")
        check("shell-metacharacter hop1_ip is rejected", False,
              "generate_config() did not raise")
    except ValueError:
        check("shell-metacharacter hop1_ip is rejected", True)
    except Exception as e:
        check("shell-metacharacter hop1_ip is rejected", False,
              f"wrong exception type: {e!r}")

    try:
        mh.generate_config(hop1_ip="", hop2_ip="5.6.7.8")
        check("empty hop1_ip is rejected", False, "generate_config() did not raise")
    except ValueError:
        check("empty hop1_ip is rejected", True)
    except Exception as e:
        check("empty hop1_ip is rejected", False, f"wrong exception type: {e!r}")

    # --- Test 5: Instructions print cleanly ---
    print("\n-- Instructions --------------------------------------")
    try:
        instr = mh.instructions()
        check("instructions() returns non-empty string", bool(instr))
        check("instructions() mentions kill switch",
              "kill switch" in instr.lower() or "Kill switch" in instr, instr[:200])
        check("instructions() lists recommended pairs", "Mullvad" in instr)
    except Exception as e:
        check("instructions() returns without error", False, str(e))

    # --- Test 6: status() ---
    print("\n-- Status dict ---------------------------------------")
    st = mh.status()
    check("status() shows hop1 conf exists", st.get("hop1_conf_exists") is True)
    check("status() shows hop2 conf exists", st.get("hop2_conf_exists") is True)
    # kill_switch_configured must reflect the actual file contents, not just
    # be a hardcoded truthy label (the dashboard previously hardcoded
    # "ACTIVE" regardless of this value).
    check("status() reports kill_switch_configured True when rule is present in both files",
          st.get("kill_switch_configured") is True)

# Restore config
_cfg.DATA_DIR            = _orig_data
_cfg.WIREGUARD_HOP1_CONF = _orig_hop1
_cfg.WIREGUARD_HOP2_CONF = _orig_hop2

# --- Summary ---
print(f"\n{'=' * 50}")
print(f"  {PASS} passed  /  {FAIL} failed")
if FAIL:
    print("  RESULT: SOME TESTS FAILED")
    sys.exit(1)
else:
    print("  RESULT: ALL TESTS PASSED")
    sys.exit(0)
