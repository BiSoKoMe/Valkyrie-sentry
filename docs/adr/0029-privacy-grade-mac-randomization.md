# ADR 0029 - Privacy-grade MAC randomisation (CSPRNG + per-network stable)

Date: 2026-07-25 . Status: accepted

## Context

MAC randomisation is one of Valkyrie's three headline pillars (detection,
blocking, randomisation). The existing `mac_randomizer.py` handled the hard,
unglamorous parts well - platform-specific application, adapter cycling with
live read-back verification, backup/restore, never-randomise guards. But the
address *generation* itself had three defects that kept it below the bar set by
the best-in-class implementations (iOS "Private Wi-Fi Address", Android
persistent randomised MAC):

1. **Non-cryptographic RNG.** Addresses were built with `random` - the Mersenne
   Twister - whose internal state (and therefore its entire past/future output
   stream) is reconstructable from a modest number of observed outputs. For a
   primitive whose *entire purpose* is unlinkability, a predictable generator is
   a real weakness.
2. **Fresh address every reconnect.** A brand-new random MAC on every link-up
   breaks captive portals and DHCP leases, and constant churn is itself
   conspicuous. The state of the art is *per-network* stability: one address per
   network, unlinkable across networks.
3. **A self-defeating address shape.** It chose a *real vendor* OUI and then set
   the locally-administered bit - a combination real hardware never exhibits, so
   the "randomised" address was trivially flaggable as randomised (arguably
   worse than either honest option).

## Decision

Rebuild address generation as pure, unit-tested functions and raise the default
behaviour to the iOS/Android bar.

- **CSPRNG everywhere.** Every random byte now comes from `secrets`
  (`token_bytes`, `choice`). `random` is gone from this module.
- **Per-network stable addresses (default).** A per-install 32-byte key
  (`MAC_KEY_PATH`, CSPRNG, owner-only perms) plus a stable network id
  (`current_network_id` - Wi-Fi SSID, else default-gateway MAC) are combined
  with `mac_for_network = HMAC-SHA256(key, iface‖network_id)`. The same network
  always yields the same address (portals/DHCP/NAC keep working, no conspicuous
  churn); different networks yield independent addresses an observer can neither
  correlate nor precompute without the secret key. When the network can't be
  identified, generation falls back to a fresh CSPRNG-random address - an
  unknown network never gets a predictable one.
- **Honest address shape.** Default is spec-compliant locally-administered (LA
  bit set, multicast clear) - the same honest, standards-clean choice iOS and
  Android make. An opt-in `MAC_VENDOR_BLEND` hides behind a real vendor OUI with
  the LA bit *clear* (a legal universally-administered address). The old
  vendor-OUI-with-LA-bit shape is never produced.
- Backward compatibility: `_generate_mac()` remains as a thin wrapper so
  existing callers keep working; `randomize()` now routes through `_next_mac()`,
  which picks per-network vs fresh-random and records which in the event log.

## Consequences

- The randomiser is now unlinkable-by-construction (CSPRNG), usable on real
  networks (per-network stability), and standards-clean (no tell-tale address
  shape) - matching the model users already trust on their phones.
- `tests/test_mac.py` gains coverage for the properties that matter: CSPRNG
  uniqueness across 2000 draws, per-network *stability* (same key+network ->
  same address), *unlinkability* (same key, different network -> different
  address), *key-dependence* (different key -> different address), correct LA/
  unicast bits in both styles, and that the derived address is not a visible
  slice of the network id. The pre-existing Windows apply/cycle failure-path
  tests are unchanged and still pass (33/33).

## Honest boundaries (what this is NOT)

- **Randomisation != anonymity.** A randomised MAC unlinks you at layer 2 across
  networks; it does nothing about higher-layer identifiers (logins, cookies,
  browser/TLS fingerprints, account activity). It is one layer, not a cloak.
- **Network identification is best-effort.** SSID/gateway detection shells out to
  OS tools (`netsh`, `iwgetid`, `ip`, `arp`) that can be absent or blocked; when
  they fail, the address is fresh-random for that session - correct, but the
  per-network *stability* benefit is lost until the network can be identified.
- **The LA bit is still visible.** Like iOS/Android, the default advertises that
  the address is locally administered. The guarantee is *unlinkability across
  networks*, not hiding the fact that randomisation is in use. Vendor-blend mode
  trades that away for OUI-collision risk and vendor impersonation - hence
  opt-in.
- **Application still depends on drivers/OS.** Some adapters and virtual/VPN NICs
  ignore or mangle a MAC change; the existing live read-back check reports that
  rather than assuming success, but it cannot force a driver that refuses.
