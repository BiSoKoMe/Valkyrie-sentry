"""Multi-hop WireGuard VPN config generator.

Generates two chained WireGuard configurations (hop1 → hop2) along with
server-setup shell scripts and human-readable instructions.

Usage:
    python -m valkyrie --setup-multihop --hop1 1.2.3.4 --hop2 5.6.7.8
"""

from __future__ import annotations

import base64
import os
import re
import struct
from pathlib import Path
from typing import Optional

from .config import (
    DATA_DIR,
    MULTIHOP_SUBNET_1,
    MULTIHOP_SUBNET_2,
    WIREGUARD_HOP1_CONF,
    WIREGUARD_HOP2_CONF,
)

# Conservative allow-list for a WireGuard Endpoint host: IPv4/IPv6 literal or
# DNS hostname (hostname labels may contain '_' in the wild, e.g. some
# corporate DNS zones, so it's included). Deliberately rejects anything
# containing shell/INI metacharacters (spaces, ';', '$', quotes, etc.) so a
# bad --hop1/--hop2 value fails loudly instead of silently producing a
# malformed config. __main__.py's HOP1_IP/HOP2_IP placeholder sentinels
# (used when --hop1/--hop2 are omitted) intentionally still match this.
_ENDPOINT_HOST_RE = re.compile(r"^[A-Za-z0-9._\-]+$")

# Recommended server pairs (informational)
RECOMMENDED_PAIRS = [
    ("Mullvad Sweden",               "ProtonVPN Switzerland"),
    ("IVPN Gibraltar",               "Mullvad Netherlands"),
    ("Self-hosted Hetzner Germany",  "Hetzner Finland"),
]

# Kill-switch iptables lines (appended to PostUp / PreDown)
_KILL_SWITCH_UP   = (
    "iptables -I OUTPUT ! -o wg+ -m mark "
    "! --mark $(wg show wg0 fwmark) -j REJECT"
)
_KILL_SWITCH_DOWN = (
    "iptables -D OUTPUT ! -o wg+ -m mark "
    "! --mark $(wg show wg0 fwmark) -j REJECT"
)


# ---------------------------------------------------------------------------
# Key generation (pure-Python Curve25519 scalar clamping)
# ---------------------------------------------------------------------------

def _generate_private_key() -> bytes:
    """Generate a clamped WireGuard private key (32 bytes)."""
    key = bytearray(os.urandom(32))
    key[0]  &= 248   # clear bits 0,1,2
    key[31] &= 127   # clear bit 7
    key[31] |= 64    # set bit 6
    return bytes(key)


def _private_to_public(private: bytes) -> bytes:
    """Compute the Curve25519 public key from a private key.

    There is deliberately NO fallback. This used to `return os.urandom(32)`
    when the `cryptography` package was missing — 32 random bytes that *look*
    like a valid WireGuard public key but have no mathematical relationship to
    the private key. A config built from such a "key" is accepted by every
    check in this module and by WireGuard's own parser, yet no peer can ever
    complete a handshake with it: a textbook silent failure (looks like it
    worked, does nothing) with no diagnostic. `cryptography` is a hard
    dependency of this project (see requirements.txt / the VPN audit report),
    so if the import fails we raise loudly rather than hand back a key that is
    guaranteed not to work.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError as exc:
        raise RuntimeError(
            "Cannot derive WireGuard public keys: the 'cryptography' package "
            "is not installed. Install it (pip install cryptography) — there "
            "is no safe fallback, since a fake public key produces a config "
            "that silently never handshakes."
        ) from exc
    priv_obj = X25519PrivateKey.from_private_bytes(private)
    return priv_obj.public_key().public_bytes_raw()


def _encode_key(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _make_keypair() -> tuple[str, str]:
    """Return (private_b64, public_b64)."""
    priv = _generate_private_key()
    pub  = _private_to_public(priv)
    return _encode_key(priv), _encode_key(pub)


# ---------------------------------------------------------------------------
# MultiHopVPN
# ---------------------------------------------------------------------------

class MultiHopVPN:
    """Generates two-hop WireGuard client configs and server setup scripts."""

    def generate_config(self, hop1_ip: str, hop2_ip: str) -> dict:
        """Generate hop1 and hop2 WireGuard configs and write to data dir.

        Returns a dict with keys: hop1_conf, hop2_conf, hop1_priv, hop2_priv,
        hop1_pub, hop2_pub, hop1_path, hop2_path, server_scripts.

        Raises ValueError if hop1_ip/hop2_ip are empty or contain characters
        that cannot appear in a WireGuard Endpoint value — this generator
        previously accepted anything (including whitespace or shell
        metacharacters) and would silently write a config with a malformed
        Endpoint line that WireGuard would refuse to parse at connect time.
        """
        for label, ip in (("hop1_ip", hop1_ip), ("hop2_ip", hop2_ip)):
            if not ip or not ip.strip():
                raise ValueError(f"{label} must not be empty")
            if not _ENDPOINT_HOST_RE.match(ip.strip()):
                raise ValueError(
                    f"{label}={ip!r} is not a valid IP/hostname for a "
                    "WireGuard Endpoint"
                )

        priv1, pub1 = _make_keypair()
        priv2, pub2 = _make_keypair()

        hop1_text = self._hop1_conf(priv1, hop1_ip)
        hop2_text = self._hop2_conf(priv2, hop2_ip)

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        WIREGUARD_HOP1_CONF.write_text(hop1_text)
        WIREGUARD_HOP2_CONF.write_text(hop2_text)

        # Server setup scripts
        s1_path = DATA_DIR / "server_setup_hop1.sh"
        s2_path = DATA_DIR / "server_setup_hop2.sh"
        s1_path.write_text(self._server_setup_script(hop_num=1, client_pub=pub1,
                                                      subnet=MULTIHOP_SUBNET_1))
        s2_path.write_text(self._server_setup_script(hop_num=2, client_pub=pub2,
                                                      subnet=MULTIHOP_SUBNET_2))
        # Make scripts executable on Unix
        try:
            s1_path.chmod(0o755)
            s2_path.chmod(0o755)
        except OSError:
            pass

        return {
            "hop1_conf":   hop1_text,
            "hop2_conf":   hop2_text,
            "hop1_priv":   priv1,
            "hop2_priv":   priv2,
            "hop1_pub":    pub1,
            "hop2_pub":    pub2,
            "hop1_path":   str(WIREGUARD_HOP1_CONF),
            "hop2_path":   str(WIREGUARD_HOP2_CONF),
            "server_scripts": [str(s1_path), str(s2_path)],
        }

    def status(self) -> dict:
        """Return status of the generated hop configs.

        `kill_switch_configured` reflects only that the PostUp/PreDown
        iptables rule is present in the config files on disk. It is NOT a
        claim that a tunnel is up or that the rule has actually been applied
        to a live interface — this class never starts wg-quick or inspects
        `iptables -S`, so real enforcement cannot be verified from here.
        Callers (e.g. the dashboard) must not render this as "ACTIVE"
        unconditionally.
        """
        hop1_exists = WIREGUARD_HOP1_CONF.exists()
        hop2_exists = WIREGUARD_HOP2_CONF.exists()
        kill_switch_configured = False
        if hop1_exists and hop2_exists:
            try:
                hop1_text = WIREGUARD_HOP1_CONF.read_text(encoding="utf-8")
                hop2_text = WIREGUARD_HOP2_CONF.read_text(encoding="utf-8")
                kill_switch_configured = (
                    _KILL_SWITCH_UP in hop1_text and _KILL_SWITCH_UP in hop2_text
                )
            except OSError:
                kill_switch_configured = False
        return {
            "hop1_conf_exists":       hop1_exists,
            "hop2_conf_exists":       hop2_exists,
            "hop1_path":              str(WIREGUARD_HOP1_CONF),
            "hop2_path":              str(WIREGUARD_HOP2_CONF),
            "kill_switch":            _KILL_SWITCH_UP,
            "kill_switch_configured": kill_switch_configured,
        }

    def instructions(self) -> str:
        """Return human-readable setup instructions."""
        lines = [
            "Multi-hop WireGuard Setup",
            "=" * 50,
            "",
            "1. Provision two VPS servers (recommended pairs below).",
            "2. Run server_setup_hop1.sh on hop-1 server.",
            "3. Run server_setup_hop2.sh on hop-2 server.",
            "4. Copy each server's public key into the matching conf file",
            "   (replace REPLACE_WITH_HOP1_PUBKEY / REPLACE_WITH_HOP2_PUBKEY).",
            "5. On hop-1 server, add hop-2 as a WireGuard peer.",
            "6. Import wg_hop1.conf and wg_hop2.conf into your WireGuard client.",
            "7. Bring up both tunnels: wg-quick up wg_hop1 && wg-quick up wg_hop2",
            "",
            "Traffic path: You → Hop 1 → Hop 2 → Internet",
            "Kill switch is ACTIVE — traffic leaks blocked if tunnel drops.",
            "",
            "Recommended server pairs:",
        ]
        for a, b in RECOMMENDED_PAIRS:
            lines.append(f"  {a}  →  {b}")
        lines += [
            "",
            f"Configs written to:",
            f"  {WIREGUARD_HOP1_CONF}",
            f"  {WIREGUARD_HOP2_CONF}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Config templates
    # ------------------------------------------------------------------

    def _hop1_conf(self, private_key: str, hop1_ip: str) -> str:
        return (
            f"[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = 10.13.13.2/32\n"
            f"DNS = 10.13.13.1\n"
            f"PostUp = {_KILL_SWITCH_UP}\n"
            f"PreDown = {_KILL_SWITCH_DOWN}\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = REPLACE_WITH_HOP1_PUBKEY\n"
            f"Endpoint = {hop1_ip}:51820\n"
            f"AllowedIPs = 10.13.14.0/24\n"
        )

    def _hop2_conf(self, private_key: str, hop2_ip: str) -> str:
        # NOTE: Endpoint must be hop2's real public IP/hostname (hop2_ip), not
        # the WireGuard-internal tunnel address (e.g. 10.13.14.1). The overlay
        # address doesn't exist on the public internet and can't be dialed to
        # perform the initial handshake — using it here previously produced a
        # config whose second hop could never connect (see
        # docs/VPN_SELFHEAL_AUDIT_REPORT.md).
        return (
            f"[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = 10.13.14.2/32\n"
            f"PostUp = {_KILL_SWITCH_UP}\n"
            f"PreDown = {_KILL_SWITCH_DOWN}\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = REPLACE_WITH_HOP2_PUBKEY\n"
            f"Endpoint = {hop2_ip}:51820\n"
            f"AllowedIPs = 0.0.0.0/0\n"
            f"PersistentKeepalive = 25\n"
        )

    def _server_setup_script(self, hop_num: int,
                              client_pub: str, subnet: str) -> str:
        gw_ip    = subnet.rsplit(".", 1)[0] + ".1"
        net_cidr = subnet
        return (
            "#!/bin/bash\n"
            "# Valkyrie multi-hop — server setup script for hop {hop_num}\n"
            "# Run as root on the VPS\n"
            "set -e\n\n"
            "apt update && apt install -y wireguard\n\n"
            "# Generate server keypair\n"
            "SERVER_PRIV=$(wg genkey)\n"
            "SERVER_PUB=$(echo \"$SERVER_PRIV\" | wg pubkey)\n"
            "echo \"Server public key: $SERVER_PUB\"\n\n"
            f"cat > /etc/wireguard/wg0.conf << EOF\n"
            f"[Interface]\n"
            f"Address = {gw_ip}/24\n"
            f"ListenPort = 51820\n"
            f"PrivateKey = $SERVER_PRIV\n\n"
            f"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; "
            f"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
            f"PreDown = iptables -D FORWARD -i wg0 -j ACCEPT; "
            f"iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n\n"
            f"[Peer]\n"
            f"# Valkyrie client\n"
            f"PublicKey = {client_pub}\n"
            f"AllowedIPs = {net_cidr}\n"
            f"EOF\n\n"
            "sysctl net.ipv4.ip_forward=1\n"
            "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf\n\n"
            "wg-quick up wg0\n"
            "systemctl enable wg-quick@wg0\n\n"
            f'echo "Hop {hop_num} server is up. Public key: $SERVER_PUB"\n'
            f'echo "Add this pubkey to your wg_hop{hop_num}.conf [Peer] section."\n'
        ).format(hop_num=hop_num)
