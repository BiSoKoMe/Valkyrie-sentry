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
from .config import DNS_LISTEN_HOST, DNS_LISTEN_PORT, UNBOUND_PORT, WEB_HOST, WEB_PORT
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

def _add_windows_firewall_rule(port: int, console) -> None:
    """Add an inbound UDP allow rule for Valkyrie DNS port (non-fatal)."""
    if platform.system() != "Windows":
        return
    rule_name = f"Valkyrie DNS UDP {port}"
    try:
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=allow",
                "protocol=UDP",
                f"localport={port}",
                "profile=any",
            ],
            check=True,
            capture_output=True,
        )
        console.print(f"[green]✓[/green] Windows Firewall rule added for UDP port {port}")
    except subprocess.CalledProcessError as exc:
        # Rule may already exist — not fatal
        console.print(f"[dim]Firewall rule skipped: {exc.stderr.decode(errors='replace').strip()}[/dim]")
    except FileNotFoundError:
        console.print("[dim]netsh not found — skipping firewall rule[/dim]")


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
        """Print a timed startup line.  Called immediately after each component starts."""
        elapsed = time.monotonic() - t0
        console.print(f"[green]✓[/green] {label} [dim]({elapsed:.2f}s)[/dim]")

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
    count = blocklist.load(console=console)
    _tick(f"Blocklist loaded ({count:,} domains)", _t)
    if args.update:
        console.print(f"[green]Update complete.[/green] {count:,} domains.")
        store.stop()
        return

    # ------------------------------------------------------------------
    # 3. Firewall (IP-level blocking — optional, non-fatal)
    # ------------------------------------------------------------------
    _t = time.monotonic()
    firewall = FirewallManager(console=console)
    if not args.no_firewall:
        firewall.start(console=console)
        _tick("Firewall ready", _t)
    else:
        console.print("[yellow]Firewall disabled (--no-firewall)[/yellow]")

    # ------------------------------------------------------------------
    # 4. Unbound local resolver (optional — degrades to external DNS)
    # ------------------------------------------------------------------
    unbound: UnboundManager | None = None
    dns_upstream_host = "8.8.8.8"
    dns_upstream_port = 53
    if not args.no_unbound:
        _t = time.monotonic()
        unbound = UnboundManager(console=console)
        if unbound.start():
            dns_upstream_host, dns_upstream_port = unbound.upstream_addr()
            _tick("Unbound resolver ready", _t)
        else:
            _tick("Unbound skipped (not installed)", _t)
    else:
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
        mac_randomizer.auto_randomize_on_connect()
        _tick("MAC randomizer started (auto-randomise on reconnect)", _t)
    else:
        console.print("[dim]MAC randomizer: disabled (use --mac-rand to enable)[/dim]")

    # ------------------------------------------------------------------
    # 7d. Multi-hop VPN (status only — configs generated via --setup-multihop)
    # ------------------------------------------------------------------
    _t = time.monotonic()
    from .multihop import MultiHopVPN
    _mh_status = MultiHopVPN().status()
    if _mh_status["hop1_conf_exists"] and _mh_status["hop2_conf_exists"]:
        _tick("Multi-hop VPN configs ready", _t)
    else:
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
        _add_windows_firewall_rule(args.port, console)
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
    else:
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
        web_thread = threading.Thread(
            target=run_server,
            kwargs={"host": args.web_host, "port": args.web_port},
            daemon=True,
            name="web-dashboard",
        )
        web_thread.start()
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
    # 12. Run
    # ------------------------------------------------------------------
    console.print("\n[bold green]Valkyrie is running.[/bold green]  Press Ctrl-C to stop.\n")

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
