# ADR 0061 - Warden: network and local-connection privacy

Date: 2026-09-11 . Status: accepted . Follows: ADR 0060

## Context

ADR 0060 named three components - Valkyrie, NYX, Aegis - and gave each one job.
None of the three own the specific question of what a device reveals simply by
being present on a network: a stable hardware identity other devices on the
same Wi-Fi can track over time, a TCP/IP stack fingerprint that survives a MAC
change, or unnecessary discovery traffic. That code already exists
(`valkyrie/mac_randomizer.py`, `valkyrie/fingerprint.py`) and is already live
in the shipped product, but it has never had a named owner in the capability
contract - it was invisible to `valkyrie/capabilities.py` even though it runs
on every boot.

The owner's explicit standard for this component, stated directly: "stop the
tracking without killing the Wi-Fi... a privacy product that disconnects the
user every time it gets nervous is not working correctly." That is a
different failure mode than anything ADR 0060 governs - NYX's failure mode is
over-observing outbound data, Valkyrie's is a missed or over-eager host
action. This component's specific, named failure mode is breaking
connectivity in the name of protecting it, so it needs its own explicit
boundary rather than being folded into an existing one.

## Decision

A fourth named component, **Warden**, owns network-presence privacy on this
device:

| Component | Owns | Does not own |
|---|---|---|
| Warden | Local-network and Wi-Fi identity exposure (MAC address presented per network), TCP/IP stack fingerprint reduction, unnecessary local-network discovery surface | Independent host enforcement, outbound content inspection (NYX's job), incident correlation (Aegis's job), and - explicitly - never disrupting connectivity as its own goal |

Warden's standing invariant, ranked above its own privacy gains: **a
protection this component applies must never be the reason a normal network
connection stops working.** Where blocking or changing something could break
connectivity, Warden must either find a way that preserves connectivity or
decline to act - it does not get to treat a broken connection as an
acceptable cost of privacy. Concretely: `mac_randomizer.py`'s existing
per-network-stable addressing already gives Warden a real foundation (an
address is deterministic per network, so devices on a trusted network are not
re-fingerprinted every reconnect) with hardened, retry-safe adapter cycling on
Windows (bounded timeouts, live-readback verification, never leaving an
adapter stranded disabled). `fingerprint.py`'s TCP/IP stack normalization is
the second existing pillar.

Warden ships today as **foundation**: real, live, already-shipping code with
real regression tests, but without the adaptive by-network-trust behavior
(home vs. public Wi-Fi posture) described in the owner's broader vision - that
is deliberately future work, not claimed here.

The machine-readable contract lives in `valkyrie/capabilities.py` alongside
the other three, served at the same `GET /api/v1/capabilities`. Warden's
`evidence` cites the already-real, already-live routes `/api/mac/status`,
`/api/mac/randomize`, `/api/mac/restore`, and `/api/fingerprint/status` -
nothing new was built to justify this registration, it makes an existing,
working capability visible in the same contract the other three already use.

## Consequences

The capability contract now accurately describes four real product surfaces
instead of three plus one invisible one. Nothing about `mac_randomizer.py` or
`fingerprint.py`'s actual behavior changes as a result of this ADR - this is
a naming and boundary decision, not an implementation change.

Future by-network-trust adaptivity (stricter posture on an unrecognized or
public-style network, explained in plain language to the user - "this
protection was disabled because blocking it would have broken your
connection") is explicitly deferred and requires its own measured rollout
before being claimed, following the same "prove it before promoting"
discipline ADR 0060 already established for the shadow-mode detection
architecture.
