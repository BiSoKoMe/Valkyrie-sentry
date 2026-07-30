"""Tests for the MAC identity layer — the wifi half of "stop tracking me".

`test_mac.py` exists but is on the host-safety exclusion list, because parts of
it touch real adapters. This file is the pure-logic half: everything here can
run on any machine, in CI, without changing a single network interface. That
split matters — it means the properties below are actually checked on every
run instead of being skipped indefinitely.

What is asserted, and why each one is load-bearing:

  * **Unicast bit clear.** A multicast source address is illegal on the wire.
    Get this wrong and the machine silently loses connectivity.
  * **Locally-administered bit set** (when not vendor-blending). Claiming a
    real manufacturer's OUI you do not own is both incorrect and more
    identifying, not less.
  * **CSPRNG, not `random`.** A predictable MAC is a tracked MAC.
  * **Stable per network, independent across networks.** This is the entire
    privacy claim: the same coffee shop should see the same address every
    visit (so the network keeps working), while two different networks must
    see addresses that cannot be linked. Break the first and wifi breaks;
    break the second and the feature does nothing.
  * **The install key is a SECRET.** Every per-network address is
    HMAC(key, network_id), so anyone who can read the key can compute every
    address the machine will ever use, on every network. Protecting that file
    is not hygiene, it is the whole mechanism.
  * **Format tolerance.** Windows reports MACs with dashes; the validator
    accepted them while the bit-parsers split on ':' only and raised
    ValueError. Accepting an input the parser cannot read is the defect.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie import secure_file as sf
from valkyrie.mac_randomizer import (
    _is_valid_mac, generate_mac, is_locally_administered, is_unicast,
    mac_for_network,
)

_HEX_MAC = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


def main() -> int:
    c = Checks("mac identity", expect_min=20)

    # ── Wire-legality of generated addresses ────────────────────────────
    print("\n[1] every generated address must be legal on the wire")
    macs = [generate_mac() for _ in range(300)]
    c.check("all generated MACs are well-formed",
            all(_is_valid_mac(m) for m in macs))
    c.check("all are uppercase colon-separated (one canonical output form)",
            all(_HEX_MAC.match(m) for m in macs))
    c.check("all are UNICAST (a multicast source address breaks networking)",
            all(is_unicast(m) for m in macs))
    c.check("all are LOCALLY ADMINISTERED (not impersonating a real vendor OUI)",
            all(is_locally_administered(m) for m in macs))

    # ── Randomness quality ──────────────────────────────────────────────
    print("\n[2] addresses must be unpredictable")
    c.check(f"300 generations produce 300 distinct addresses "
            f"(got {len(set(macs))})", len(set(macs)) == 300)
    # The last 5 octets are the random payload; the first carries the flag bits.
    tails = {m[3:] for m in macs}
    c.check(f"the random payload is not repeating ({len(tails)} distinct tails)",
            len(tails) == 300)

    # ── Vendor blend keeps the address legal ────────────────────────────
    print("\n[3] vendor-blend mode is still wire-legal")
    blends = [generate_mac(vendor_blend=True) for _ in range(100)]
    c.check("blended MACs are well-formed", all(_is_valid_mac(m) for m in blends))
    c.check("blended MACs are still unicast", all(is_unicast(m) for m in blends))
    c.check("blended MACs are NOT locally-administered (that is the point — "
            "they sit behind a real OUI)",
            all(not is_locally_administered(m) for m in blends))

    # ── The privacy claim: stable per network, unlinkable across ────────
    print("\n[4] THE privacy property: stable per network, unlinkable across")
    key_a = b"\x01" * 32
    home1 = mac_for_network(key_a, "wifi:HomeNet")
    home2 = mac_for_network(key_a, "wifi:HomeNet")
    cafe = mac_for_network(key_a, "wifi:CoffeeShop")
    airport = mac_for_network(key_a, "wifi:Airport")
    c.check("SAME network + same key -> SAME address (wifi keeps working)",
            home1 == home2)
    c.check("DIFFERENT networks -> DIFFERENT addresses (cannot be correlated)",
            len({home1, cafe, airport}) == 3)
    c.check("per-network addresses are wire-legal too",
            all(_is_valid_mac(m) and is_unicast(m) for m in (home1, cafe, airport)))
    c.check("per-network addresses are locally administered",
            all(is_locally_administered(m) for m in (home1, cafe, airport)))

    # ── The key is what makes it unpredictable ──────────────────────────
    print("\n[5] the install key is what makes addresses unpredictable")
    key_b = b"\x02" * 32
    c.check("a DIFFERENT install key gives a different address for the same "
            "network (so the key, not the SSID, is the secret)",
            mac_for_network(key_b, "wifi:HomeNet") != home1)
    many = {mac_for_network(key_a, f"wifi:net{i}") for i in range(200)}
    c.check(f"200 networks -> 200 distinct addresses (got {len(many)})",
            len(many) == 200)

    # ── REGRESSION: the install key must not be world-readable ──────────
    # Found 2026-07-30: _load_or_create_key only chmod'd on POSIX
    # (`if os.name == "posix"`), so on Windows the key sat readable by
    # BUILTIN\Users. Anyone reading it can compute every address the machine
    # will ever use, on every network -- defeating cross-network unlinkability
    # entirely. The docstring claimed protection "where the platform supports
    # it", which misdescribed Windows as unsupported.
    print("\n[6] REGRESSION: the install key must be protected on ALL platforms")
    with tempfile.TemporaryDirectory() as td:
        keyfile = Path(td) / "mac_key.bin"
        keyfile.write_bytes(b"\x00" * 32)
        ok, detail = sf.harden(keyfile)
        c.check(f"the key file can be protected on this platform ({detail[:50]})",
                ok is True)
        ok2, _ = sf.verify(keyfile)
        c.check("verification confirms it is not world-readable", ok2 is True)

    # ── REGRESSION: dash-separated MACs must not crash ──────────────────
    # Windows reports MACs with dashes (ipconfig / getmac / the registry).
    # _is_valid_mac accepted them; is_unicast/is_locally_administered split on
    # ':' only and raised ValueError on the very format the validator allowed.
    print("\n[7] REGRESSION: Windows dash-format MACs must parse, not raise")
    dash = "02-00-00-11-22-33"
    colon = "02:00:00:11:22:33"
    c.check("the validator accepts dash format", _is_valid_mac(dash))
    try:
        du, dl = is_unicast(dash), is_locally_administered(dash)
        raised = False
    except Exception:
        du = dl = None
        raised = True
    c.check("is_unicast/is_locally_administered do NOT raise on dash format",
            not raised)
    c.check("dash and colon forms agree on the unicast bit",
            du == is_unicast(colon))
    c.check("dash and colon forms agree on the LA bit",
            dl == is_locally_administered(colon))

    # ── Robustness ──────────────────────────────────────────────────────
    print("\n[8] malformed input is rejected, not crashed on")
    for bad in ("", "not-a-mac", "AA:BB:CC", "GG:HH:II:JJ:KK:LL",
                "AA:BB:CC:DD:EE:FF:00"):
        c.check(f"rejects {bad!r}", not _is_valid_mac(bad))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
