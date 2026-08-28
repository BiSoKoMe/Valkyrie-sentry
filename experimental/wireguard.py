"""WireGuard config generator.

WireGuard is a kernel module - Valkyrie cannot install it.
This module generates ready-to-use server and client config files,
prints setup instructions, and optionally renders a QR code for
mobile import.

Run via:  python -m valkyrie --setup-wireguard --server-ip <PUBLIC_IP>

Generated files (in data/):
  wg0.conf         - server config
  wg_client.conf   - first client config template

Keys are generated fresh each time and never stored in source code.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Optional

from .config import (
    DATA_DIR,
    WIREGUARD_CLIENT_ADDR,
    WIREGUARD_CLIENT_PATH,
    WIREGUARD_CONF_PATH,
    WIREGUARD_PORT,
    WIREGUARD_SERVER_ADDR,
)

_SYSTEM = platform.system()


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def _wg_genkey() -> tuple[str, str]:
    """Generate a WireGuard keypair using the `wg` binary.

    Returns (private_key, public_key) as base64 strings.
    Raises RuntimeError if `wg` is not found.
    """
    wg = shutil.which("wg")
    if not wg:
        raise RuntimeError("`wg` binary not found — WireGuard is not installed")

    genkey = subprocess.run([wg, "genkey"], capture_output=True, check=True)
    privkey = genkey.stdout.decode().strip()

    pubkey_proc = subprocess.run(
        [wg, "pubkey"],
        input    = genkey.stdout,
        capture_output = True,
        check    = True,
    )
    pubkey = pubkey_proc.stdout.decode().strip()
    return privkey, pubkey


# ---------------------------------------------------------------------------
# Config templates
# ---------------------------------------------------------------------------

def _server_conf(
    private_key: str,
    server_addr: str,
    listen_port: int,
    dns_ip: str,
    iface: str = "eth0",
) -> str:
    return textwrap.dedent(f"""\
        [Interface]
        PrivateKey = {private_key}
        Address = {server_addr}
        ListenPort = {listen_port}

        # Route all peer traffic through this machine and Valkyrie DNS
        PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; \\
                   iptables -A FORWARD -o wg0 -j ACCEPT; \\
                   iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE; \\
                   iptables -A INPUT -p udp --dport {listen_port} -j ACCEPT
        PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; \\
                   iptables -D FORWARD -o wg0 -j ACCEPT; \\
                   iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE; \\
                   iptables -D INPUT -p udp --dport {listen_port} -j ACCEPT

        # Peers are added below — one [Peer] block per device.
        # Generate a keypair for each device with: wg genkey | tee priv | wg pubkey
        #
        # [Peer]
        # PublicKey = <client_public_key>
        # AllowedIPs = 10.13.13.2/32
    """)


def _client_conf(
    client_private_key: str,
    client_addr: str,
    server_public_key: str,
    server_endpoint: str,
    dns_ip: str,
) -> str:
    return textwrap.dedent(f"""\
        [Interface]
        PrivateKey = {client_private_key}
        Address = {client_addr}
        DNS = {dns_ip}          # Valkyrie DNS — all queries routed here

        [Peer]
        PublicKey = {server_public_key}
        Endpoint = {server_endpoint}:{WIREGUARD_PORT}
        AllowedIPs = 0.0.0.0/0, ::/0   # route ALL traffic through Valkyrie
        PersistentKeepalive = 25
    """)


# ---------------------------------------------------------------------------
# Install instructions
# ---------------------------------------------------------------------------

def _install_instructions() -> str:
    linux = textwrap.dedent("""
        Linux (server):
          sudo apt install wireguard          # Debian/Ubuntu
          sudo dnf install wireguard-tools    # Fedora/RHEL
          sudo pacman -S wireguard-tools      # Arch
    """)
    windows = textwrap.dedent("""
        Windows:
          Download the official installer:
          https://download.wireguard.com/windows-client/wireguard-installer.exe
          Then import wg_client.conf via the WireGuard app UI.
    """)
    macos = textwrap.dedent("""
        macOS:
          brew install wireguard-tools
          Or download from the App Store: "WireGuard"
    """)
    mobile = textwrap.dedent("""
        iOS / Android:
          Install the WireGuard app from App Store / Google Play.
          Import wg_client.conf by scanning the QR code printed above,
          or copy the file manually.
    """)
    return linux + windows + macos + mobile


def _print_qr(client_conf_text: str, console=None) -> None:
    """Print a QR code of the client config if qrencode is available."""
    qrencode = shutil.which("qrencode")
    if not qrencode:
        return
    try:
        result = subprocess.run(
            [qrencode, "-t", "ANSIUTF8"],
            input          = client_conf_text.encode(),
            capture_output = True,
            check          = True,
        )
        qr_text = result.stdout.decode(errors="replace")
        if console:
            console.print("\n[bold]Client QR code (scan with WireGuard mobile app):[/bold]")
            console.print(qr_text)
        else:
            print("\nClient QR code (scan with WireGuard mobile app):")
            print(qr_text)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# WireGuardConfig
# ---------------------------------------------------------------------------

class WireGuardConfig:
    """Generates WireGuard server and client configuration files.

    Does not start WireGuard - that is left to the user via wg-quick.
    """

    def __init__(self, console=None) -> None:
        self._console = console

    def _print(self, msg: str) -> None:
        import re
        if self._console:
            self._console.print(msg)
        else:
            print(re.sub(r"\[/?[^\]]+\]", "", msg))

    def available(self) -> bool:
        """Return True if the `wg` binary is in PATH."""
        return shutil.which("wg") is not None

    def generate(self, server_ip: str, iface: str = "eth0") -> dict:
        """Generate server and client config files.

        Args:
            server_ip: Public IP / hostname of the WireGuard server.
            iface:     Outbound network interface on the server (for NAT).

        Returns a dict with keys:
            server_conf, client_conf, server_pubkey, client_pubkey
        """
        if not self.available():
            self._print(
                "[yellow]`wg` not found.[/yellow] WireGuard is not installed.\n"
                + _install_instructions()
            )
            return {}

        self._print("[bold cyan]Generating WireGuard keypairs…[/bold cyan]")

        server_priv, server_pub = _wg_genkey()
        client_priv, client_pub = _wg_genkey()

        # DNS IP is the WireGuard server-side tunnel IP (gateway)
        dns_ip = WIREGUARD_SERVER_ADDR.split("/")[0]

        server_text = _server_conf(
            private_key = server_priv,
            server_addr = WIREGUARD_SERVER_ADDR,
            listen_port = WIREGUARD_PORT,
            dns_ip      = dns_ip,
            iface       = iface,
        )
        client_text = _client_conf(
            client_private_key = client_priv,
            client_addr        = WIREGUARD_CLIENT_ADDR,
            server_public_key  = server_pub,
            server_endpoint    = server_ip,
            dns_ip             = dns_ip,
        )

        WIREGUARD_CONF_PATH.write_text(server_text,  encoding="utf-8")
        WIREGUARD_CLIENT_PATH.write_text(client_text, encoding="utf-8")
        # Both files contain a `PrivateKey =` line - the VPN identity itself.
        # Anyone who reads one can impersonate this peer and decrypt its
        # traffic, so they get the same treatment as the TLS CA key. DATA_DIR
        # inherits a BUILTIN\Users:read ACE from %ProgramData% on Windows, so
        # without this they would be readable by every local account.
        from .secure_file import harden as _harden_secret
        for _p in (WIREGUARD_CONF_PATH, WIREGUARD_CLIENT_PATH):
            _ok, _detail = _harden_secret(_p)
            if not _ok:
                self._print(f"[yellow]! Could not restrict {_p.name}: "
                            f"{_detail}[/yellow]")

        self._print(f"[green]✓[/green] Server config  : {WIREGUARD_CONF_PATH}")
        self._print(f"[green]✓[/green] Client config  : {WIREGUARD_CLIENT_PATH}")
        self._print(f"[dim]  Server public key: {server_pub}[/dim]")
        self._print(f"[dim]  Client public key: {client_pub}[/dim]")

        _print_qr(client_text, self._console)
        self._print_setup_instructions(server_ip)

        return {
            "server_conf":   WIREGUARD_CONF_PATH,
            "client_conf":   WIREGUARD_CLIENT_PATH,
            "server_pubkey": server_pub,
            "client_pubkey": client_pub,
        }

    def _print_setup_instructions(self, server_ip: str) -> None:
        dns_ip = WIREGUARD_SERVER_ADDR.split("/")[0]
        self._print(textwrap.dedent(f"""
            [bold]Setup instructions[/bold]

            [bold cyan]On the server[/bold cyan] (Linux — must have WireGuard kernel module):
              1. Copy wg0.conf to /etc/wireguard/wg0.conf
              2. Enable IP forwarding:
                   echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
                   sudo sysctl -p
              3. Start the tunnel:
                   sudo wg-quick up wg0
              4. Enable at boot:
                   sudo systemctl enable wg-quick@wg0

            [bold cyan]On each client device[/bold cyan]:
              iOS/Android : Scan the QR code above with the WireGuard app
              Windows     : WireGuard app → Import tunnel → select wg_client.conf
              Linux       : sudo wg-quick up ./wg_client.conf
              macOS       : brew install wireguard-tools
                            sudo wg-quick up ./wg_client.conf

            [bold cyan]Add more clients[/bold cyan]:
              Run: python -m valkyrie --setup-wireguard --server-ip {server_ip}
              Each run generates a fresh client keypair.
              Add the [Peer] block from the new wg_client.conf to wg0.conf.

            [bold cyan]DNS routing[/bold cyan]:
              Client DNS is set to {dns_ip} (the WireGuard gateway).
              All client DNS queries will be handled by Valkyrie running
              on the server, giving remote devices full sinkhole protection.

            [bold cyan]Verify the tunnel[/bold cyan]:
              sudo wg show                   # check peer handshake
              curl -s https://ifconfig.me    # should show server IP
        """))
