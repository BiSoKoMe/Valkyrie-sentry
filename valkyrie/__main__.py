"""Entry point — python -m valkyrie.


Wires all components together and starts the engine.

Usage:
  python -m valkyrie              # full shield (DNS + behavioral + DoH detection)
  python -m valkyrie --update     # force blocklist update then exit
  python -m valkyrie --no-dns     # skip DNS interceptor (behavioral + DoH only)
  python -m valkyrie --port 5353  # custom DNS listen port
  python -m valkyrie --no-ui      # headless mode (log to stdout)
"""

from __future__ import annotations

import sys
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import argparse
import platform
import subprocess
import threading
import time
import webbrowser


# ---------------------------------------------------------------------------
# Dependency check — fail loudly before importing anything
# ---------------------------------------------------------------------------

_REQUIRED = {
    "psutil":   "pip install psutil",
    "rich":     "pip install rich",
    "yaml":     "pip install pyyaml",
    "dns":      "pip install dnspython",
}

_missing = []
for mod, install_cmd in _REQUIRED.items():
    try:
        __import__(mod)
    except ImportError:
        _missing.append((mod, install_cmd))

if _missing:
    print("Missing dependencies — install them and retry:\n")
    for mod, cmd in _missing:
        print(f"  {mod:12s}  →  {cmd}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Local imports (after dependency check)
# ---------------------------------------------------------------------------

from rich.console import Console

from .behavioral import BehavioralEngine
from .blocklist import BlocklistManager
from .config import DNS_LISTEN_HOST, DNS_LISTEN_PORT, WEB_HOST, WEB_PORT
from .dns_interceptor import DNSInterceptor
from .doh_detector import DoHDetector
from .firewall import FirewallManager
from .process_watcher import ProcessWatcher
from .resolver import UnboundManager
from .rules import RulesLoader
from .store import Store
from .ui import Dashboard
from .wireguard import WireGuardConfig


# ---------------------------------------------------------------------------
# Windows firewall helper
# ---------------------------------------------------------------------------

def _add_windows_firewall_rule(port: int, console=None) -> None:
    """Add inbound + outbound UDP allow rules for Valkyrie DNS (non-fatal).

    `console` may be None (normal, quiet startup); when None, per-rule output
    is suppressed and only the firewall changes are applied.
    """
    def _say(msg: str) -> None:
        if console is not None:
            console.print(msg)

    if platform.system() != "Windows":
        return

    rules = [
        # Inbound: accept DNS queries arriving at our listen port
        {"name": f"Valkyrie DNS Inbound UDP {port}", "dir": "in",
         "protocol": "UDP", "localport": str(port)},
        # Outbound UDP: forward queries to upstream resolvers
        {"name": "Valkyrie DNS Outbound UDP", "dir": "out",
         "protocol": "UDP", "remoteport": "53"},
        # Outbound TCP: TCP fallback when UDP is blocked/dropped
        {"name": "Valkyrie DNS Outbound TCP", "dir": "out",
         "protocol": "TCP", "remoteport": "53"},
    ]

    for rule in rules:
        args = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule['name']}",
            f"dir={rule['dir']}",
            "action=allow",
            f"protocol={rule['protocol']}",
            "profile=any",
        ]
        if "localport" in rule:
            args.append(f"localport={rule['localport']}")
        if "remoteport" in rule:
            args.append(f"remoteport={rule['remoteport']}")
        try:
            subprocess.run(args, check=True, capture_output=True)
            _say(f"[green]✓[/green] Firewall rule: {rule['name']}")
        except subprocess.CalledProcessError as exc:
            _say(f"[dim]Firewall rule skipped ({rule['name']}): "
                 f"{exc.stderr.decode(errors='replace').strip()}[/dim]")
        except FileNotFoundError:
            _say("[dim]netsh not found — skipping firewall rules[/dim]")
            break


# ---------------------------------------------------------------------------
# Upstream reachability probe
# ---------------------------------------------------------------------------

def _test_upstream() -> bool:
    """Send a raw UDP DNS query for github.com to verify outbound port 53 works.

    Uses a hand-crafted wire packet so this works even if dnspython is broken.
    Returns True if any upstream responds within 2 seconds.
    """
    import socket, struct
    # Minimal A-record query for github.com (transaction ID 0xAABB)
    wire = (b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x06github\x03com\x00\x00\x01\x00\x01')
    for upstream in ["40.54.1.13", "8.8.8.8", "1.1.1.1"]:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(wire, (upstream, 53))
            sock.recvfrom(4096)
            return True
        except OSError:
            # Unreachable/timeout for this upstream — try the next one.
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return False


# ---------------------------------------------------------------------------
# Startup status box
# ---------------------------------------------------------------------------

def _print_status_box(console, rows) -> None:
    """Render the boxed "VALKYRIE IS RUNNING" summary from live service rows.

    Args:
        console: Rich console to print to.
        rows:    list of (label, ok, detail) tuples — ok=False renders a red ✗.
    """
    from rich import box as _box
    from rich.panel import Panel
    from rich.table import Table

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="left", no_wrap=True)
    grid.add_column(justify="center", no_wrap=True)
    grid.add_column(justify="left")
    for label, ok, detail in rows:
        mark = "[green]✓[/green]" if ok else "[red]✗[/red]"
        grid.add_row(f"[bold]{label}[/bold]", mark, f"[dim]{detail}[/dim]")

    console.print()
    console.print(Panel(
        grid,
        title="[bold green]VALKYRIE IS RUNNING[/bold green]",
        box=_box.DOUBLE,
        border_style="green",
        expand=False,
        padding=(1, 3),
    ))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="valkyrie",
        description="Local privacy gateway — DNS sinkhole + behavioral heuristics",
    )
    parser.add_argument("--update",    action="store_true",  help="Force blocklist update then exit")
    parser.add_argument("--no-dns",    action="store_true",  help="Skip DNS interceptor")
    parser.add_argument("--no-ui",     action="store_true",  help="Headless mode")
    parser.add_argument("--port",      type=int, default=DNS_LISTEN_PORT, help="DNS listen port")
    parser.add_argument("--host",      type=str, default=DNS_LISTEN_HOST, help="DNS listen host")
    parser.add_argument("--build-baseline", action="store_true", help="Rebuild process baselines now")
    parser.add_argument("--no-firewall",  action="store_true",  help="Skip kernel IP firewall")
    parser.add_argument("--no-unbound",   action="store_true",  help="Skip local Unbound resolver")
    parser.add_argument("--setup-wireguard", action="store_true",
                        help="Generate WireGuard configs and print setup instructions, then exit")
    parser.add_argument("--server-ip", type=str, default="YOUR_SERVER_IP",
                        help="Public IP for --setup-wireguard (e.g. 203.0.113.1)")
    parser.add_argument("--wg-iface", type=str, default="eth0",
                        help="Server network interface for WireGuard NAT (default: eth0)")
    parser.add_argument("--test-dns", metavar="DOMAIN", nargs="?", const="google.com",
                        help="Self-test the DNS interceptor and exit (default domain: google.com)")
    parser.add_argument("--web",      action="store_true",  help="Start web dashboard")
    parser.add_argument("--web-port", type=int, default=WEB_PORT, help=f"Web dashboard port (default: {WEB_PORT})")
    parser.add_argument("--web-host", type=str, default=WEB_HOST, help=f"Web dashboard host (default: {WEB_HOST})")
    parser.add_argument("--service-status", action="store_true", help="Print Windows service status and exit")
    parser.add_argument("--tls",      action="store_true",  help="Enable TLS inspection (mitmproxy)")
    parser.add_argument("--no-tls",   action="store_true",  help="Explicitly disable TLS inspection (default)")
    parser.add_argument("--kill-telemetry",    action="store_true", help="Scan, confirm, then disable Windows telemetry")
    parser.add_argument("--restore-telemetry", action="store_true", help="Restore telemetry settings from backup")
    parser.add_argument("--strict", action="store_true",
                         help="Enable strict mode: apply blocklist on top of scanner decisions")
    parser.add_argument("--mac-rand",    action="store_true", help="Enable auto MAC randomisation on reconnect")
    parser.add_argument("--mac-restore", action="store_true", help="Restore original MACs from backup and exit")
    parser.add_argument("--mac-status",  action="store_true", help="Print current vs original MACs and exit")
    parser.add_argument("--setup-multihop", action="store_true",
                        help="Generate multi-hop WireGuard configs and exit")
    parser.add_argument("--hop1", type=str, default="", help="Hop-1 server IP for --setup-multihop")
    parser.add_argument("--hop2", type=str, default="", help="Hop-2 server IP for --setup-multihop")
    parser.add_argument("--multihop-status", action="store_true", help="Print multi-hop VPN config status and exit")
    parser.add_argument("--zero-log",        action="store_true",  help="RAM-only mode — no disk writes")
    parser.add_argument("--zero-log-import", type=int, default=0, metavar="HOURS",
                        help="Import last N hours from disk DB into RAM at startup")
    parser.add_argument("--debug", action="store_true",
                        help="Verbose DNS forwarding logs — prints every query, upstream tried, and result")
    args = parser.parse_args()

    console = Console()

    # ------------------------------------------------------------------
    # Early-exit: WireGuard config generator
    # ------------------------------------------------------------------
    if args.setup_wireguard:
        wg = WireGuardConfig(console=console)
        wg.generate(server_ip=args.server_ip, iface=args.wg_iface)
        return

    # ------------------------------------------------------------------
    # Early-exit: service status
    # ------------------------------------------------------------------
    if args.service_status:
        from .service_manager import get_service_status, is_running_as_service
        console.print(f"Service status : [bold]{get_service_status()}[/bold]")
        console.print(f"This process   : [bold]{'service' if is_running_as_service() else 'terminal'}[/bold]")
        return

    # ------------------------------------------------------------------
    # Early-exit: telemetry killer
    # ------------------------------------------------------------------
    if args.kill_telemetry:
        from .telemetry_killer import TelemetryKiller
        tk = TelemetryKiller()
        findings = tk.scan()
        if not findings:
            console.print("[yellow]Could not scan — admin rights required.[/yellow]")
            return
        console.print("[bold]Telemetry scan:[/bold]")
        for name, info in findings.items():
            state_str = "[red]ACTIVE[/red]" if info.get("active") else "[green]already disabled[/green]"
            console.print(f"  {name:30s} {state_str}")
        console.print("\n[bold yellow]This will modify the Windows registry and disable telemetry services.[/bold yellow]")
        confirm = console.input("Proceed? [y/N]: ").strip().lower()
        if confirm != "y":
            console.print("Cancelled.")
            return
        results = tk.kill()
        for name, ok in results.items():
            console.print(f"  {name:30s} {'[green]OK[/green]' if ok else '[red]FAILED[/red]'}")
        return

    if args.restore_telemetry:
        from .telemetry_killer import TelemetryKiller
        tk = TelemetryKiller()
        results = tk.restore()
        for name, ok in results.items():
            console.print(f"  {name:30s} {'[green]restored[/green]' if ok else '[red]FAILED[/red]'}")
        return

    # ------------------------------------------------------------------
    # Early-exit: MAC status / restore
    # ------------------------------------------------------------------
    if args.mac_status or args.mac_restore:
        from .mac_randomizer import MacRandomizer
        mac = MacRandomizer()
        if args.mac_restore:
            result = mac.restore()
            console.print(f"[green]Restored:[/green] {result or '(nothing to restore)'}")
            return
        status = mac.status()
        for iface, info in status.items():
            changed = " [yellow](randomised)[/yellow]" if info["changed"] else ""
            console.print(f"  {iface:20s}  current={info['current'] or '?'}  "
                          f"original={info['original'] or '?'}{changed}")
        return

    # ------------------------------------------------------------------
    # Early-exit: multi-hop setup
    # ------------------------------------------------------------------
    if args.setup_multihop:
        from .multihop import MultiHopVPN
        mh   = MultiHopVPN()
        hop1 = args.hop1 or "HOP1_IP"
        hop2 = args.hop2 or "HOP2_IP"
        cfg  = mh.generate_config(hop1_ip=hop1, hop2_ip=hop2)
        console.print(f"[green]✓[/green] Configs written:")
        console.print(f"  {cfg['hop1_path']}")
        console.print(f"  {cfg['hop2_path']}")
        console.print(f"\n[dim]{mh.instructions()}[/dim]")
        return

    if args.multihop_status:
        from .multihop import MultiHopVPN
        st = MultiHopVPN().status()
        for k, v in st.items():
            console.print(f"  {k:25s} {v}")
        return

    def _tick(label: str, t0: float) -> None:
        """Print a timed per-component startup line — only in --debug mode.

        In normal mode startup output is just the final status box, so these
        progress lines (and the sub-component chatter routed through
        `_verbose` below) are suppressed to keep the console clean.
        """
        if not args.debug:
            return
        elapsed = time.monotonic() - t0
        console.print(f"[green]✓[/green] {label} [dim]({elapsed:.2f}s)[/dim]")

    # Sub-components accept a Rich console for progress output; give them one
    # only in debug mode so normal startup stays quiet (Improvement 6).
    _verbose = console if args.debug else None

    # ------------------------------------------------------------------
    # 0. Zero-log mode (must run before Store so we pass RAM URI)
    # ------------------------------------------------------------------
    zero_log = None
    if args.zero_log:
        from .zero_log import ZeroLogMode
        zero_log = ZeroLogMode()
        zero_log.enable()
        console.print("[bold yellow]WARNING: Zero log mode: no data written to disk[/bold yellow]")
        console.print("[dim]Session data exists in RAM only. Power off to wipe all traces.[/dim]")

    # ------------------------------------------------------------------
    # 1. Store
    # ------------------------------------------------------------------
    _t = time.monotonic()
    if zero_log is not None:
        store = zero_log.make_ram_store()
        zero_log._store = store
    else:
        store = Store()
    store.start()
    if zero_log and args.zero_log_import > 0:
        imported = zero_log.import_from_disk(store, args.zero_log_import)
        console.print(f"[dim]  Imported {imported:,} events from last {args.zero_log_import}h[/dim]")
    _tick("SQLite store ready", _t)

    # ------------------------------------------------------------------
    # 2. Blocklist
    # ------------------------------------------------------------------
    _t = time.monotonic()
    blocklist = BlocklistManager()
    count = blocklist.load(console=_verbose)
    _tick(f"Blocklist loaded ({count:,} domains)", _t)
    if args.update:
        console.print(f"[green]Update complete.[/green] {count:,} domains.")
        store.stop()
        return

    # ------------------------------------------------------------------
    # 3. Firewall (IP-level blocking — optional, non-fatal)
    # ------------------------------------------------------------------
    _t = time.monotonic()
    firewall = FirewallManager(console=_verbose)
    if not args.no_firewall:
        firewall.start(console=_verbose)
        _tick("Firewall ready", _t)
    elif args.debug:
        console.print("[yellow]Firewall disabled (--no-firewall)[/yellow]")

    # ------------------------------------------------------------------
    # 4. Unbound local resolver (optional — degrades to external DNS)
    # ------------------------------------------------------------------
    unbound: UnboundManager | None = None
    unbound_ok = False
    dns_upstream_host = "8.8.8.8"
    dns_upstream_port = 53
    if not args.no_unbound:
        _t = time.monotonic()
        unbound = UnboundManager(console=_verbose)
        if unbound.start():
            unbound_ok = True
            dns_upstream_host, dns_upstream_port = unbound.upstream_addr()
            _tick("Unbound resolver ready", _t)
        else:
            _tick("Unbound skipped (not installed)", _t)
    elif args.debug:
        console.print("[yellow]Unbound disabled (--no-unbound)[/yellow]")

    # ------------------------------------------------------------------
    # 5. Rules
    # ------------------------------------------------------------------
    _t = time.monotonic()
    rules = RulesLoader()
    rules.start()
    _tick("User rules loaded", _t)

    # ------------------------------------------------------------------
    # 6. Process watcher
    # ------------------------------------------------------------------
    _t = time.monotonic()
    proc_watcher = ProcessWatcher()
    proc_watcher.start()
    _tick("Process watcher started", _t)

    # ------------------------------------------------------------------
    # 7. Behavioral engine
    # ------------------------------------------------------------------
    _t = time.monotonic()
    behavioral = BehavioralEngine()
    _tick("Behavioral heuristics ready", _t)

    # ------------------------------------------------------------------
    # 7b. Site scanner
    # ------------------------------------------------------------------
    _t = time.monotonic()
    from .site_scanner import SiteScanner
    scanner = SiteScanner(store=store)
    _tick("Site scanner ready", _t)
    if args.strict:
        console.print("[yellow]  Strict mode: blocklist applied on top of scanner[/yellow]")

    # ------------------------------------------------------------------
    # 7c. MAC randomizer (optional)
    # ------------------------------------------------------------------
    mac_randomizer = None
    if args.mac_rand:
        _t = time.monotonic()
        from .mac_randomizer import MacRandomizer
        mac_randomizer = MacRandomizer(store=store)
        new_mac = mac_randomizer.randomize()
        if new_mac:
            console.print(f"[green]✓[/green] MAC randomised: [cyan]{new_mac}[/cyan]")
        elif mac_randomizer.last_error:
            console.print(f"[red]✗ MAC randomisation failed:[/red] {mac_randomizer.last_error}")
        mac_randomizer.auto_randomize_on_connect()
        _tick("MAC randomizer: active (auto-randomise on reconnect)", _t)
    elif args.debug:
        console.print("[dim]MAC randomizer: disabled (use --mac-rand to enable)[/dim]")

    # ------------------------------------------------------------------
    # 7d. Multi-hop VPN (status only — configs generated via --setup-multihop)
    # ------------------------------------------------------------------
    _t = time.monotonic()
    from .multihop import MultiHopVPN
    _mh_status = MultiHopVPN().status()
    if _mh_status["hop1_conf_exists"] and _mh_status["hop2_conf_exists"]:
        _tick("Multi-hop VPN configs ready", _t)
    elif args.debug:
        console.print("[dim]Multi-hop VPN: no configs (run --setup-multihop --hop1 IP --hop2 IP)[/dim]")

    # ------------------------------------------------------------------
    # 8. Dashboard
    # ------------------------------------------------------------------
    dashboard: Dashboard | None = None
    if not args.no_ui:
        dashboard = Dashboard(store=store, console=console, firewall=firewall)

    def doh_alert_cb(proc_name: str, ip: str, pid: int) -> None:
        msg = f"[bold red]  DoH bypass:[/bold red] {proc_name} (pid {pid}) -> {ip}:443"
        if dashboard:
            dashboard.push_doh_alert(proc_name, ip, pid)
        else:
            console.print(msg)

    # ------------------------------------------------------------------
    # 9. DoH detector
    # ------------------------------------------------------------------
    _t = time.monotonic()
    doh = DoHDetector(store=store, on_alert=doh_alert_cb)
    doh.start()
    _tick("DoH detector started", _t)

    # ------------------------------------------------------------------
    # 10. DNS interceptor
    # ------------------------------------------------------------------
    _t = time.monotonic()
    dns_server: DNSInterceptor | None = None
    if not args.no_dns:
        _add_windows_firewall_rule(args.port, _verbose)
        if _test_upstream():
            if args.debug:
                console.print("[green]✓ Upstream DNS reachable[/green]")
        else:
            console.print("[red]WARNING: Cannot reach upstream DNS servers. "
                          "Check firewall / network.[/red]")
        dns_server = DNSInterceptor(
            store           = store,
            blocklist       = blocklist,
            behavioral      = behavioral,
            rules           = rules,
            process_watcher = proc_watcher,
            scanner         = scanner,
            strict          = args.strict,
            host            = args.host,
            port            = args.port,
            upstream_host   = dns_upstream_host,
            upstream_port   = dns_upstream_port,
            debug           = args.debug,
        )
        try:
            dns_server.start()
            _tick(f"DNS sinkhole on 0.0.0.0:{args.port} -> {dns_upstream_host}:{dns_upstream_port}", _t)
            if platform.system() == "Linux":
                console.print(
                    f"[dim]  Redirect OS DNS:[/dim]\n"
                    f"  [cyan]sudo iptables -t nat -A OUTPUT -p udp --dport 53 "
                    f"-j REDIRECT --to-port {args.port}[/cyan]"
                )
        except PermissionError:
            console.print(f"[red]✗ Cannot bind port {args.port} — try sudo or use --port 5353[/red]")
            dns_server = None
    elif args.debug:
        console.print("[yellow]DNS interceptor disabled (--no-dns)[/yellow]")

    # ------------------------------------------------------------------
    # 8a. Self-test mode
    # ------------------------------------------------------------------
    if args.test_dns:
        if dns_server is None:
            console.print("[red]DNS interceptor failed to start — cannot run self-test.[/red]")
            store.stop()
            return
        time.sleep(0.2)   # let the serve loop come up
        domain = args.test_dns
        console.print(f"\n[bold]DNS self-test →[/bold] querying [cyan]{domain}[/cyan] …")
        result = dns_server.self_test(domain)
        if result["decision"] == "PASS":
            ip     = result.get("ip", "?")
            rcode  = result.get("rcode", "?")
            blocked = ip in ("0.0.0.0", "::", None) or rcode == "NXDOMAIN"
            verdict = "[bold red]BLOCKED[/bold red]" if blocked else "[bold green]ALLOWED[/bold green]"
            console.print(f"  Result : {verdict}")
            console.print(f"  IP     : {ip}")
            console.print(f"  Rcode  : {rcode}")
            console.print(f"  Answers: {result.get('answers', 0)}")
        else:
            console.print(f"  [bold red]FAIL[/bold red] — {result.get('error', 'unknown error')}")
        dns_server.stop()
        store.stop()
        return

    # ------------------------------------------------------------------
    # 9. Baseline builder (background)
    # ------------------------------------------------------------------
    def _baseline_loop() -> None:
        while True:
            time.sleep(3600)    # check every hour
            if store.should_build_baseline():
                store.build_baselines()

    if args.build_baseline:
        if store.should_build_baseline():
            store.build_baselines()
            console.print("[green]✓[/green] Baselines rebuilt.")
        else:
            console.print("[yellow]Not enough data yet — need 24h of events.[/yellow]")
    else:
        threading.Thread(target=_baseline_loop, daemon=True, name="baseline").start()

    # ------------------------------------------------------------------
    # 10. Web dashboard (optional)
    # ------------------------------------------------------------------
    if args.web:
        from .web.server import state as web_state, run_server
        web_state.store          = store
        web_state.firewall       = firewall
        web_state.blocklist      = blocklist
        web_state.start_time     = time.time()
        web_state.mac_randomizer = mac_randomizer
        web_state.zero_log       = zero_log
        web_state.dns_port       = args.port
        web_state.web_port       = args.web_port
        web_thread = threading.Thread(
            target=run_server,
            kwargs={"host": args.web_host, "port": args.web_port},
            daemon=True,
            name="web-dashboard",
        )
        web_thread.start()
        if args.debug:
            console.print(
                f"[green]✓[/green] Web dashboard  "
                f"[cyan]http://localhost:{args.web_port}[/cyan]"
            )

    # ------------------------------------------------------------------
    # 11. TLS inspection (optional — disabled by default)
    # ------------------------------------------------------------------
    tls_inspector = None
    if args.tls and not args.no_tls:
        from .tls_inspector import TLSInspector
        tls_inspector = TLSInspector(store=store, blocklist=blocklist, behavioral=behavioral, rules=rules)
        if tls_inspector.start():
            ca_path = tls_inspector.setup_ca()
            console.print(f"[green]✓[/green] TLS inspector on port {tls_inspector.port}")
            console.print(f"[dim]  Configure your browser proxy: 127.0.0.1:{tls_inspector.port}[/dim]")
            console.print(f"[dim]  CA certificate: {ca_path}[/dim]")
        else:
            console.print(
                "[yellow]TLS inspection unavailable — install mitmproxy: "
                "pip install mitmproxy[/yellow]"
            )
            tls_inspector = None

    # ------------------------------------------------------------------
    # 12. Startup status box (real values) + auto-open dashboard
    # ------------------------------------------------------------------
    status_rows: list[tuple[str, bool, str]] = []

    if not args.no_dns:
        if dns_server is not None:
            status_rows.append(("DNS Sinkhole", True, f"port {args.port}"))
        else:
            status_rows.append(("DNS Sinkhole", False, f"could not bind port {args.port}"))
    if not args.no_firewall:
        status_rows.append(("Firewall", True, f"{firewall.count():,} IP ranges"))
    status_rows.append(("Behavioral AI", True, "active"))
    if unbound_ok:
        status_rows.append(("Recursive DNS", True, f"Unbound {dns_upstream_host}:{dns_upstream_port}"))
    else:
        status_rows.append(("Upstream DNS", True, f"{dns_upstream_host}:{dns_upstream_port}"))
    if zero_log is not None and zero_log.is_active():
        status_rows.append(("Zero Log", True, "RAM only (no disk)"))
    else:
        status_rows.append(("Logging", True, "disk (persistent)"))
    if mac_randomizer is not None:
        status_rows.append(("MAC Random", True, "auto on reconnect"))
    if tls_inspector is not None:
        status_rows.append(("TLS Inspect", True, f"port {tls_inspector.port}"))
    web_url = f"http://localhost:{args.web_port}"
    if args.web:
        status_rows.append(("Dashboard", True, f"localhost:{args.web_port}"))

    _print_status_box(console, status_rows)

    all_ok = all(ok for _, ok, _ in status_rows)
    console.print()
    if all_ok:
        console.print("  [bold]Protection:[/bold] [bold green]ACTIVE[/bold green]")
    else:
        console.print("  [bold]Protection:[/bold] [bold yellow]DEGRADED[/bold yellow] — see ✗ above")
    if args.web:
        console.print(f"  Open dashboard: [cyan]{web_url}[/cyan]")
    console.print("  [dim]Press Ctrl-C to stop.[/dim]\n")

    # Auto-open the dashboard in the browser, but only for an interactive
    # session with the web UI enabled — never when headless (--no-ui) or when
    # running under the Service Control Manager (no desktop session).
    if args.web and not args.no_ui:
        from .service_manager import is_running_as_service
        if not is_running_as_service():
            try:
                webbrowser.open(web_url)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 13. Run
    # ------------------------------------------------------------------
    try:
        if dashboard:
            dashboard.run()     # blocks until Ctrl-C
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[dim]Shutting down…[/dim]")
        if dns_server:
            dns_server.stop()
        if unbound:
            unbound.stop()
        if tls_inspector:
            tls_inspector.stop()
        if mac_randomizer:
            mac_randomizer.stop()
        firewall.stop()
        store.stop()
        if zero_log:
            zero_log.disable()
        console.print("[green]Done.[/green]")


if __name__ == "__main__":
    main()
