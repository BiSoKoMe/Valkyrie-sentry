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
from .config import (
    DATA_DIR,
    DNS_LISTEN_HOST,
    DNS_LISTEN_PORT,
    INTELLIGENCE_MODE,
    WEB_HOST,
    WEB_PORT,
)
from .dns_interceptor import DNSInterceptor
from .doh_detector import DoHDetector
from .firewall import FirewallManager
from .process_watcher import ProcessWatcher
from .resolver import UnboundManager
from .rules import RulesLoader
from .store import Store
from .ui import Dashboard
# wireguard / multihop / fleet / mcp / compliance moved to experimental/ —
# frozen, not deleted. See experimental/README.md and ADR 0044.


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


def build_status_rows(
    *, args, dns_server=None, firewall=None, edr_engine=None, intelligence=None,
    unbound_ok=False, dns_upstream_host="", dns_upstream_port=0,
    allow_external_fallback=True, zero_log=None, mac_randomizer=None,
    tls_inspector=None, heartbeat=None, sysmon_result=None,
) -> list[tuple[str, bool, str]]:
    """Build the (label, ok, detail) rows for the startup status box.

    Extracted from ``main()`` so it can be tested. This is the surface that
    tells a user whether they are protected, which puts it in the same category
    as ``self_test.HeartbeatMonitor``: a bug that renders a component green
    while it is down is worse than a crash, because the user acts on it.

    Pure — reads only its arguments and returns rows. Kept as a free function
    rather than a method precisely so a test can hand it a dead DNS server and
    assert the row goes red, without starting anything.

    TEST_PLAN tier 3.16 calls for the rest of ``main()``'s wiring to be
    extracted the same way. That work is deliberately NOT done blind: the
    startup path binds DNS ports and edits firewall rules, so it cannot be
    executed on a developer host to prove an extraction preserved behaviour.
    See the tier 3.16 note in docs/TEST_PLAN.md.
    """
    rows: list[tuple[str, bool, str]] = []

    if not args.no_dns:
        if dns_server is not None:
            rows.append(("DNS Sinkhole", True, f"port {args.port}"))
        else:
            rows.append(("DNS Sinkhole", False,
                         f"could not bind port {args.port}"))
    if not args.no_firewall:
        # The firewall is optional/non-fatal at startup, so it can legitimately
        # be None here. The inline version called firewall.count() regardless,
        # which raised AttributeError and took the whole status box down. It
        # renders RED instead: the user asked for a firewall and has not got
        # one, and silently omitting the row would be the same lie the DNS row
        # is careful not to tell.
        if firewall is not None:
            rows.append(("Firewall", True, f"{firewall.count():,} IP ranges"))
        else:
            rows.append(("Firewall", False, "failed to initialise"))
    rows.append(("Behavioral AI", True, "active"))
    if edr_engine is not None:
        _es = edr_engine.stats()
        rows.append(("EDR", True,
                     f"{_es['plugins']} plugins, "
                     f"{_es['incidents_open']} open incidents"))
    if intelligence is not None:
        _ist = intelligence.status()
        if _ist["learning"]:
            rows.append(("Intelligence", True,
                         f"learning (day {_ist['learning_day']} of "
                         f"{_ist['learning_days_total']})"))
        else:
            rows.append(("Intelligence", True,
                         f"active — {_ist['threats_learned']:,} threats learned"))
    if unbound_ok:
        rows.append(("Recursive DNS", True,
                     f"Unbound {dns_upstream_host}:{dns_upstream_port}"))
    else:
        rows.append(("Upstream DNS", True,
                     f"{dns_upstream_host}:{dns_upstream_port}"))
    if not allow_external_fallback:
        rows.append(("DNS Leak Guard", True, "local resolver only (fail-closed)"))
    else:
        rows.append(("DNS Leak Guard", False,
                     "public-DNS fallback ENABLED (install Unbound)"))
    if zero_log is not None and zero_log.is_active():
        rows.append(("Zero Log", True, "RAM only (no disk)"))
    else:
        rows.append(("Logging", True, "disk (persistent)"))
    if mac_randomizer is not None:
        rows.append(("MAC Random", True, "auto on reconnect"))
    if tls_inspector is not None:
        rows.append(("TLS Inspect", True, f"port {tls_inspector.port}"))
    if heartbeat is not None:
        rows.append(("Heartbeat", True, "self-check every 15s"))
    if sysmon_result is not None:
        # Degraded is a MAIN path, not an edge case (ADR 0048) — this row
        # goes red on it deliberately, the same way every other row here
        # does, rather than being hidden or softened into a footnote.
        rows.append(("Sysmon", not sysmon_result.degraded,
                     sysmon_result.reason if sysmon_result.degraded
                     else sysmon_result.mode))
    if args.web:
        rows.append(("Dashboard", True, f"localhost:{args.web_port}"))
    return rows


def protection_state(rows) -> str:
    """'ACTIVE' only if every row is ok, else 'DEGRADED'.

    Separated from rendering so the rule cannot drift from what is displayed:
    a single red row must never still read ACTIVE.
    """
    return "ACTIVE" if all(ok for _, ok, _ in rows) else "DEGRADED"


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
    # --setup-wireguard / --server-ip / --wg-iface removed: WireGuard moved to
    # experimental/ (Valkyrie is not a VPN product). See experimental/README.md.
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
    parser.add_argument("--version", action="store_true",
                        help="Print the Valkyrie version + build stamp and exit "
                             "(so 'which build is installed?' is never ambiguous).")
    parser.add_argument("--mac-status",  action="store_true", help="Print current vs original MACs and exit")
    parser.add_argument("--privacy",     action="store_true",
                        help="Privacy pillar ON at startup: randomise the MAC and "
                             "spoof the TCP/IP fingerprint every boot (the installed "
                             "service runs with this).")
    # --setup-multihop / --hop1 / --hop2 / --multihop-status removed with the
    # multi-hop VPN (experimental/).
    parser.add_argument("--zero-log",        action="store_true",  help="RAM-only mode — no disk writes")
    parser.add_argument("--zero-log-import", type=int, default=0, metavar="HOURS",
                        help="Import last N hours from disk DB into RAM at startup")
    parser.add_argument("--meeting-on",  action="store_true", help="Meeting Mode: block ALL outbound traffic (kill switch), then exit")
    parser.add_argument("--meeting-off", action="store_true", help="Deactivate Meeting Mode and restore normal traffic, then exit")
    parser.add_argument("--meeting-status", action="store_true", help="Print Meeting Mode status and exit")
    parser.add_argument("--fingerprint", action="store_true", help="Normalise TCP/IP fingerprint (TTL 64, no timestamps), then exit")
    parser.add_argument("--fingerprint-restore", action="store_true", help="Restore original TCP/IP fingerprint, then exit")
    parser.add_argument("--fingerprint-status", action="store_true", help="Print TCP/IP fingerprint status and exit")
    parser.add_argument("--siem", type=str, default="", metavar="URL",
                        help="Export EDR incidents to a SIEM: udp://host:514, "
                             "tcp://host:514, tls://host:6514 or file:///path "
                             "(off by default — sends event data off this machine)")
    parser.add_argument("--siem-format", type=str, default="cef",
                        choices=("cef", "json"), help="SIEM export format (default: cef)")
    parser.add_argument("--siem-dns", action="store_true",
                        help="Also export blocked/flagged DNS events to the SIEM "
                             "(includes domains — explicit opt-in)")
    parser.add_argument("--skip-selftest", action="store_true", help="Skip the startup self-test (not recommended)")
    parser.add_argument("--enable-native-audit", action="store_true",
                        help="Turn on Windows process-creation auditing (Security 4688 + "
                             "command line) so command-line detection works WITHOUT Sysmon, "
                             "then exit. Needs admin.")
    parser.add_argument("--debug", action="store_true",
                        help="Verbose DNS forwarding logs — prints every query, upstream tried, and result")
    parser.add_argument("--intelligence-status", action="store_true",
                        help="Print learning status and learned-intelligence stats, then exit")
    parser.add_argument("--reset-learning", action="store_true",
                        help="Wipe the learned baseline and restart the learning period, then exit")
    parser.add_argument("--export-intelligence", action="store_true",
                        help="Export learned intelligence to data/intelligence_export.json, then exit")
    parser.add_argument("--no-intelligence", action="store_true",
                        help="Disable the self-learning intelligence layer")
    parser.add_argument("--no-edr", action="store_true",
                        help="Disable the EDR layer (incidents, hunting, response)")
    parser.add_argument("--no-sysmon-setup", action="store_true",
                        help="Skip Sysmon install/verify at startup — Valkyrie still "
                             "runs, but command-line, process-injection and "
                             "credential-dump detection may run in degraded mode "
                             "without it. For hosts where Sysmon is managed "
                             "separately, or for testing.")
    parser.add_argument("--no-ransomware-shield", action="store_true",
                        help="Disable the behavioral ransomware shield (canary tripwires)")
    parser.add_argument("--no-amsi", action="store_true",
                        help="Disable AMSI content scanning (OS antimalware verdicts "
                             "on script blocks and files)")
    parser.add_argument("--edr-plugin-dir", type=str, default="",
                        help="Directory to load third-party EDR plugins from "
                             "(detection/responder/enrichment). Opt-in; trusted code only")
    parser.add_argument("--endpoint", action="store_true",
                        help="(Default; kept for compatibility.) Enable endpoint "
                             "process/persistence/network telemetry and real-time "
                             "sensors feeding the EDR layer")
    parser.add_argument("--no-endpoint", action="store_true",
                        help="DNS-only mode: disable endpoint telemetry and real-time "
                             "sensors. Endpoint detection is ON BY DEFAULT so a shipped "
                             "install is fully armed however it is launched — this flag "
                             "opts out")
    parser.add_argument("--incidents", action="store_true",
                        help="Print current EDR incidents and exit")
    parser.add_argument("--hunt", type=str, default="", metavar="HUNT",
                        help="Run a saved threat hunt by id and exit "
                             "(use --hunt list to see available hunts)")
    parser.add_argument("--analyze", type=str, default="", metavar="URL",
                        help="Genuinely analyze a site's CONTENT and exit: fetch the page and "
                             "score fingerprinting, cryptomining, obfuscated JS, phishing and "
                             "tracker density. List-free — it judges what the site actually does.")
    # --mcp / --allow-response removed with the MCP server (experimental/).
    parser.add_argument("--download-lists", action="store_true",
                        help="Force-enable downloading external blocklist/threat-intel feeds "
                             "for this run, even if USE_EXTERNAL_LISTS is False in config.py "
                             "(default: on — see --no-download-lists to opt out)")
    parser.add_argument("--no-download-lists", action="store_true",
                        help="Opt OUT of downloading external blocklist/IP/threat-intel feeds "
                             "for this run — stay on the built-in seed list + learned "
                             "intelligence only, with zero outbound fetches at startup")
    parser.add_argument("--no-dns-leak", action="store_true",
                        help="Fail-closed DNS: only ever use the local resolver upstream; "
                             "never fall back to public resolvers (auto-enabled when Unbound is active)")
    # --fleet-* removed with the fleet control plane (experimental/).
    args = parser.parse_args()

    # Frozen exe double-clicked with no arguments: start the dashboard and let
    # the browser auto-open to the right port, so a user never has to pass
    # flags or guess a port. Running from source, or with any flag, is
    # unchanged. (len(sys.argv)==1 means "no args beyond the program name".)
    if getattr(sys, "frozen", False) and len(sys.argv) == 1:
        args.web = True

    console = Console()

    # Surface any active config-file/environment overrides up front, so an
    # operator can see at a glance that a non-default setting is in effect
    # (and where it came from). No output at all on a stock deployment.
    from . import config as _config
    for _ov in getattr(_config, "CONFIG_OVERRIDES", []):
        console.print(
            f"[cyan]config:[/cyan] {_ov.key} = {_ov.value!r} "
            f"[dim](from {_ov.source})[/dim]"
        )

    # ------------------------------------------------------------------
    # Early-exit: intelligence status / reset / export
    # ------------------------------------------------------------------
    if args.intelligence_status or args.reset_learning or args.export_intelligence:
        from .intelligence import Intelligence
        store = Store()
        store.start()
        intel = Intelligence(store)
        intel.start()
        try:
            if args.reset_learning:
                confirm = console.input(
                    "[bold yellow]This wipes the learned baseline and restarts "
                    "the 7-day learning period. Proceed? [y/N]: [/bold yellow]"
                ).strip().lower()
                if confirm == "y":
                    intel.reset_learning()
                    console.print("[green]✓[/green] Learning reset — baseline wiped, learning restarts now.")
                else:
                    console.print("Cancelled.")
            elif args.export_intelligence:
                import json as _json
                data = intel.export()
                out = DATA_DIR / "intelligence_export.json"
                out.write_text(_json.dumps(data, indent=2), encoding="utf-8")
                console.print(f"[green]✓[/green] Intelligence exported → [cyan]{out}[/cyan]")
                console.print(f"  Threats learned : {len(data['threats']):,}")
                console.print(f"  Safe patterns   : {len(data['safe']):,}")
            else:
                st = intel.status()
                mode = (f"LEARNING (day {st['learning_day']} of {st['learning_days_total']})"
                        if st["learning"] else "ACTIVE")
                console.print(f"[bold]Intelligence mode  :[/bold] {mode}")
                console.print(f"  Threats learned  : {st['threats_learned']:,}")
                console.print(f"  Safe patterns    : {st['safe_patterns']:,}")
                console.print(f"  Processes profiled: {st['baseline_processes']:,}")
                console.print(f"  Baseline pairs   : {st['baseline_pairs']:,}")
                if st["last_anomaly"]:
                    la = st["last_anomaly"]
                    console.print(f"  Last anomaly     : {la['domain']} ({la['decision']}, {la['score']})")
                    console.print(f"                     {la['explanation']}")
        finally:
            intel.stop()
            store.stop()
        return

    # ------------------------------------------------------------------
    # Early-exit: enable native process-creation auditing, then exit.
    # ------------------------------------------------------------------
    if args.enable_native_audit:
        from . import native_audit
        ok, detail = native_audit.enable_process_auditing()
        colour = "green" if ok else "yellow"
        console.print(f"[{colour}]Native process auditing: {detail}[/{colour}]")
        if ok:
            console.print("[dim]Command-line detection now works without Sysmon "
                          "(Valkyrie reads Security event 4688).[/dim]")
        else:
            console.print("[dim]Run this from an elevated (Administrator) prompt.[/dim]")
        return

    # ------------------------------------------------------------------
    # Early-exit: genuine site content analysis (fetch + score, then exit)
    # ------------------------------------------------------------------
    if args.analyze:
        from .site_analyzer import SiteAnalyzer
        console.print(f"[bold]Analyzing site content:[/bold] {args.analyze}")
        v = SiteAnalyzer().analyze_url(args.analyze)
        if not v.fetched:
            console.print(f"[yellow]Could not fetch the page[/yellow] "
                          f"({'; '.join(v.reasons) or 'unreachable'})")
            return
        colour = {"block": "red", "flag": "yellow", "allow": "green"}.get(v.decision, "white")
        console.print(f"  Verdict  : [{colour}]{v.decision.upper()}[/{colour}]  "
                      f"(score {v.score}; category: {v.category})")
        if v.reasons:
            console.print("  Evidence :")
            for r in v.reasons:
                console.print(f"    - {r}")
        else:
            console.print("  Evidence : none — the page content looks clean")
        console.print(f"  Signals  : {v.signals}")
        return

    # ------------------------------------------------------------------
    # Early-exit: EDR incidents / threat hunt (read-only, then exit)
    # ------------------------------------------------------------------
    if args.incidents or args.hunt:
        from .edr import EdrEngine
        store = Store()
        store.start()
        engine = EdrEngine(store)
        engine.start()
        try:
            if args.hunt:
                if args.hunt == "list":
                    console.print("[bold]Available threat hunts:[/bold]")
                    for h in engine.saved_hunts():
                        console.print(f"  [cyan]{h['id']:20s}[/cyan] {h['description']}")
                else:
                    res = engine.run_saved_hunt(args.hunt, limit=50)
                    if res.get("error"):
                        console.print(f"[red]{res['error']}[/red] "
                                      f"(try --hunt list)")
                    else:
                        console.print(f"[bold]Hunt '{args.hunt}':[/bold] "
                                      f"{res['count']} result(s)")
                        for row in res.get("rows", [])[:50]:
                            console.print(f"  {row}")
            else:  # --incidents
                incs = engine.list_incidents(limit=100)
                if not incs:
                    console.print("[dim]No incidents recorded yet.[/dim]")
                else:
                    console.print(f"[bold]{len(incs)} incident(s):[/bold]")
                    for i in incs:
                        col = {"critical": "red", "high": "red", "medium": "yellow",
                               "low": "green"}.get(i["severity"], "white")
                        console.print(
                            f"  [{col}]{i['severity']:8s}[/{col}] "
                            f"[{i['status']:13s}] {i['title']}  "
                            f"[dim]({i['detection_count']} detections)[/dim]")
        finally:
            engine.stop()
            store.stop()
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
    # Early-exit: version + build stamp
    # ------------------------------------------------------------------
    if args.version:
        from . import __version__
        try:
            from ._build import BUILD_STAMP
        except Exception:
            BUILD_STAMP = "dev (unstamped source run)"
        print(f"Valkyrie {__version__}  ·  build {BUILD_STAMP}")
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
    # Early-exit: Meeting Mode (network kill switch)
    # ------------------------------------------------------------------
    if args.meeting_on or args.meeting_off or args.meeting_status:
        from .meeting_mode import MeetingMode
        mm = MeetingMode()
        if args.meeting_on:
            console.print("[bold red]Activating Meeting Mode — blocking ALL outbound traffic…[/bold red]")
            res = mm.activate()
        elif args.meeting_off:
            console.print("[bold]Deactivating Meeting Mode — restoring normal traffic…[/bold]")
            res = mm.deactivate()
        else:
            res = mm.status()
        if res.get("error"):
            console.print(f"[red]✗ {res['error']}[/red]")
        elif res.get("active"):
            console.print(f"[bold red]MEETING MODE ACTIVE[/bold red] — outbound blocked "
                          f"(since {res.get('activated_at', '?')}, {res.get('duration_minutes', 0)} min)")
        else:
            console.print("[green]Meeting Mode is OFF[/green] — traffic normal.")
        return

    # ------------------------------------------------------------------
    # Early-exit: TCP/IP fingerprint normalisation
    # ------------------------------------------------------------------
    if args.fingerprint or args.fingerprint_restore or args.fingerprint_status:
        from .fingerprint import NetworkFingerprint
        fp = NetworkFingerprint()
        if args.fingerprint:
            ok = fp.normalize()
            console.print("[green]✓ Fingerprint normalised[/green] (TTL 64, TCP timestamps off)"
                          if ok else f"[red]✗ {fp.last_error}[/red]")
        elif args.fingerprint_restore:
            ok = fp.restore()
            console.print("[green]✓ Fingerprint restored[/green]"
                          if ok else f"[red]✗ {fp.last_error}[/red]")
        else:
            st = fp.status()
            console.print(f"  Supported     : {st['supported']}")
            console.print(f"  Default TTL   : {st['ttl']}  "
                          f"({'normalised' if st['ttl_normalized'] else 'not normalised'})")
            console.print(f"  TCP timestamps: {st['tcp_timestamps']}  "
                          f"({'normalised' if st['timestamps_normalized'] else 'not normalised'})")
            console.print(f"  Overall       : {'NORMALISED' if st['normalized'] else 'default'}")
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
    # Startup self-test — refuse to announce "protected" from a broken state
    # ------------------------------------------------------------------
    if not args.skip_selftest:
        from .self_test import preflight, critical_failures
        checks = preflight(
            port         = args.port,
            host         = args.host,
            want_dns     = not args.no_dns,
            want_unbound = not args.no_unbound,
            want_tls     = args.tls and not args.no_tls,
        )
        fatal = critical_failures(checks)
        if fatal or args.debug:
            for c in checks:
                mark = "[green]✓[/green]" if c.ok else ("[red]✗[/red]" if c.critical else "[yellow]![/yellow]")
                console.print(f"  {mark} {c.name}: [dim]{c.detail}[/dim]")
        if fatal:
            console.print()
            console.print("[bold red]Startup aborted — critical checks failed:[/bold red]")
            for c in fatal:
                console.print(f"  [red]✗ {c.name}: {c.detail}[/red]")
            console.print("[dim]Fix the above and retry, or pass --skip-selftest to override.[/dim]")
            sys.exit(1)

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
        if args.debug:
            # --debug prints every resolved domain to stdout, which is a
            # persistent trace (terminal scrollback, redirected logs) that
            # defeats the point of zero-log. Suppress the per-query domain
            # printing while zero-log is active; other startup diagnostics are
            # unaffected. See docs/TLS_ZEROLOG_AUDIT_REPORT.md.
            console.print("[dim]  Zero-log: per-domain --debug output suppressed "
                          "(would leave a domain trace on the terminal).[/dim]")

    # ------------------------------------------------------------------
    # 0. Secret hygiene — re-assert file permissions before anything runs.
    #
    #    A single audit found FOUR secrets written world-readable on Windows
    #    (TLS CA private key, MAC install key, API control token, fleet
    #    enrolment token), all for the same reason: DATA_DIR inherits a
    #    BUILTIN\Users:read ACE from %ProgramData%, so anything written there
    #    is readable by every local account unless something prevents it.
    #    Each write site is now fixed, but this sweep is the backstop — it
    #    heals a secret left exposed by an older build, and catches a future
    #    write site that forgets. Idempotent and cheap; already-restricted
    #    files are skipped.
    # ------------------------------------------------------------------
    try:
        from .secure_file import harden_known_secrets
        _healed = harden_known_secrets()
        for _label, _p, _ok, _detail in _healed:
            if _ok:
                console.print(f"[dim]  Secured {_label} ({_p.name})[/dim]")
            else:
                console.print(f"[yellow]  ! {_label} ({_p.name}) is readable by "
                              f"other local accounts: {_detail}[/yellow]")
    except Exception as _exc:      # noqa: BLE001 — never block startup
        console.print(f"[yellow]  ! secret permission sweep failed: {_exc}[/yellow]")

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
    # --update / --download-lists force a download; --no-download-lists forces
    # the opposite (stay on the built-in seed list + cache only, no fetches);
    # otherwise defer to config.USE_EXTERNAL_LISTS (default True — see config.py).
    _dl = (True if (args.update or args.download_lists)
           else (False if args.no_download_lists else None))
    # PROTECTION MUST NEVER WAIT ON THE NETWORK. Startup always loads from
    # seed + cache (instant, offline-safe); the feed refresh happens on a
    # background thread afterwards and hot-swaps under the same lock the DNS
    # path reads through. `--update` is the one case that stays synchronous,
    # because there the user explicitly asked to refresh and exit.
    #
    # Enabling downloads by default without this made the engine block on a
    # ~500k-domain fetch before protecting anything — minutes on a slow link,
    # indistinguishable from a hang, and a hard failure in the offline /
    # air-gapped environments this product specifically targets.
    # `test_startup_smoke` caught it: 9/9 passing -> timing out.
    count = blocklist.load(console=_verbose,
                           allow_download=True if args.update else False)
    _tick(f"Blocklist loaded ({count:,} domains)", _t)
    if _dl is not False and not args.update:
        if blocklist.start_background_refresh(console=_verbose):
            _tick("Blocklist refresh started (background)", _t)

    # 2b. Threat-intel IOC feeds (abuse.ch C2/malware indicators). Same
    # download policy as the blocklist; cached feeds always load offline.
    # An intel hit is incident-grade: it blocks at DNS, sinkholes resolved
    # C2 addresses, and flags live connections through the EDR pipeline.
    _t = time.monotonic()
    from .threat_intel import ThreatIntelManager
    threat_intel = ThreatIntelManager()
    # Cache-only at startup, same rule as the blocklist above: protection must
    # never wait on the network. Offline, a synchronous load would stall for up
    # to 30s PER FEED on urllib timeouts before the engine came up. The
    # background daemon started below does the first refresh ~20s later.
    ioc_count = threat_intel.load(console=_verbose,
                                  allow_download=True if args.update else False)
    _tick(f"Threat intel loaded ({ioc_count:,} IOCs)", _t)
    if args.update:
        console.print(f"[green]Update complete.[/green] {count:,} domains, "
                      f"{ioc_count:,} IOCs.")
        store.stop()
        return
    threat_intel.start(allow_download=_dl)   # periodic refresh (no-op if downloads off)

    # ------------------------------------------------------------------
    # 3. Firewall (IP-level blocking — optional, non-fatal)
    # ------------------------------------------------------------------
    _t = time.monotonic()
    firewall = FirewallManager(console=_verbose)
    if not args.no_firewall:
        firewall.start(console=_verbose, allow_download=_dl)
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

    # No-leak DNS policy: fail-closed (local upstream only, no public-resolver
    # fallback) whenever Unbound is the upstream, or when forced via
    # --no-dns-leak / config.DNS_LOCAL_ONLY. Without a local resolver and
    # without the flag, external fallback stays on so DNS still resolves.
    from .config import DNS_LOCAL_ONLY
    force_local_only = args.no_dns_leak or DNS_LOCAL_ONLY
    allow_external_fallback = not (unbound_ok or force_local_only)
    if not allow_external_fallback:
        if unbound_ok:
            console.print("[green]✓[/green] No-leak DNS: local resolver only, "
                          "no public-DNS fallback [dim](Unbound active)[/dim]")
        else:
            # Forced fail-closed with no local resolver present: queries will
            # SERVFAIL rather than leak — the safe choice when the user asked.
            console.print("[yellow]No-leak DNS forced (--no-dns-leak) but no local "
                          "resolver is active — queries will SERVFAIL until Unbound "
                          "is available (no external fallback).[/yellow]")

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
    # 7b-2. Intelligence layer (self-learning threat detection)
    # ------------------------------------------------------------------
    intelligence = None
    if INTELLIGENCE_MODE and not args.no_intelligence:
        _t = time.monotonic()
        from .intelligence import Intelligence
        intelligence = Intelligence(store, behavioral=behavioral)
        intelligence.start()
        _st = intelligence.status()
        if _st["learning"]:
            _tick(f"Intelligence learning (day {_st['learning_day']} of "
                  f"{_st['learning_days_total']})", _t)
        else:
            _tick(f"Intelligence active ({_st['threats_learned']:,} threats learned)", _t)
    elif args.debug:
        console.print("[yellow]Intelligence layer disabled[/yellow]")

    # ------------------------------------------------------------------
    # 7c. MAC randomizer (optional)
    # ------------------------------------------------------------------
    mac_randomizer = None
    if args.mac_rand or args.privacy:
        _t = time.monotonic()
        from .mac_randomizer import MacRandomizer
        mac_randomizer = MacRandomizer(store=store)
        # Randomise NOW (every boot) so each start presents a fresh hardware
        # identity; the original is backed up so the UI can show original → new.
        new_mac = mac_randomizer.randomize()
        if new_mac:
            console.print(f"[green]✓[/green] MAC randomised: [cyan]{new_mac}[/cyan]")
        elif mac_randomizer.last_error:
            console.print(f"[red]✗ MAC randomisation failed:[/red] {mac_randomizer.last_error}")
        mac_randomizer.auto_randomize_on_connect()
        _tick("MAC randomizer: active (auto-randomise on reconnect)", _t)
    elif args.debug:
        console.print("[dim]MAC randomizer: disabled (use --mac-rand / --privacy to enable)[/dim]")

    # 7c-2. TCP/IP fingerprint spoofing (privacy pillar) — runs on start, not
    # only via the --fingerprint early-exit. Makes the box present a generic
    # (TTL 64, no TCP timestamps) stack instead of an identifiable Windows one,
    # so MAC randomisation isn't undone by an obvious OS fingerprint. Fully
    # reversible (backup); needs admin (the SYSTEM service has it).
    if args.privacy:
        _t = time.monotonic()
        try:
            from .fingerprint import NetworkFingerprint
            _fp = NetworkFingerprint()
            if _fp.normalize():
                _tick("TCP/IP fingerprint spoofed (generic stack: TTL 64, no timestamps)", _t)
            elif getattr(_fp, "last_error", ""):
                console.print(f"[dim]TCP/IP fingerprint spoof skipped: {_fp.last_error}[/dim]")
        except Exception as _exc:      # noqa: BLE001 — privacy is best-effort
            console.print(f"[dim]TCP/IP fingerprint spoof unavailable ({_exc})[/dim]")

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
    # 9f. Background page-content analysis.
    #     site_analyzer.py has always been able to judge a page by what it
    #     actually loads and runs — cryptominers, fingerprinting, packed JS,
    #     phishing — which is how an unknown domain gets a real verdict rather
    #     than a blocklist lookup. Until now its ONLY caller was the manual
    #     `--analyze <url>` command, so the capability shipped switched off.
    #     ContentWatcher runs it continuously off the DNS path (never inline:
    #     _decide is synchronous with a live query waiting). Auto-blocking is
    #     deliberately limited to near-certain categories — see the FP policy
    #     in content_watch.py.
    # ------------------------------------------------------------------
    _t = time.monotonic()
    content_watch = None
    if not args.no_dns:
        from .content_watch import ContentWatcher
        content_watch = ContentWatcher(store=store, intelligence=intelligence)
        content_watch.start()
        _tick("Page-content analysis started", _t)

    # ------------------------------------------------------------------
    # 9e. Resolution log — records ALLOWED DNS answers (dns_interceptor.py)
    #     so the list-free network scorer (network_score.py S2) can ask "was
    #     this destination ever resolved here?" without any feed or list. A
    #     hardcoded-IP C2 skips DNS entirely, which is exactly what this
    #     catches. Always on: a bounded, pure in-memory structure, and a
    #     no-op cost when nothing reads it (e.g. --no-dns / network collector
    #     unavailable).
    # ------------------------------------------------------------------
    from .resolution_log import ResolutionLog
    from .resolution_log import set_active as _set_active_resolution_log
    _set_active_resolution_log(ResolutionLog())

    # ------------------------------------------------------------------
    # 9h. Sysmon — a first-class dependency, not an optional extra. See
    #     docs/adr/0048-sysmon-dependency.md: without it, T1055/T1003.001 are
    #     undetectable and command-line detection falls back to a racy 2s
    #     poller. install_or_verify() never raises and never blocks startup —
    #     a blocked/failed install (measured live: a mainstream consumer AV's
    #     self-defense can silently remove the driver with no uninstall
    #     trail) degrades detection and is reported plainly, it does not
    #     prevent Valkyrie from running.
    # ------------------------------------------------------------------
    _t = time.monotonic()
    sysmon_result = None
    if not args.no_sysmon_setup:
        from .sysmon_manager import install_or_verify
        try:
            sysmon_result = install_or_verify()
        except Exception as exc:      # noqa: BLE001 — belt-and-suspenders on
            # top of install_or_verify()'s own internal guards: this step must
            # be able to fail in a way nobody anticipated without taking the
            # whole agent down with it. Reported exactly like any other
            # degraded mode, not swallowed silently.
            from .sysmon_manager import SysmonEnvironment, SysmonInstallResult
            sysmon_result = SysmonInstallResult(
                "unknown_error", True,
                f"Sysmon setup raised unexpectedly ({type(exc).__name__}: {exc}); "
                "continuing without it.", SysmonEnvironment())
        if sysmon_result.degraded:
            console.print(f"[yellow]Sysmon: {sysmon_result.mode} — "
                          f"{sysmon_result.reason}[/yellow]")
        else:
            _tick(f"Sysmon verified ({sysmon_result.mode})", _t)

    # ------------------------------------------------------------------
    # 9g. Deception endpoint — DECEIVE answers a tracker beacon instead of
    #     resolving it to a dead end (0.0.0.0), which was a relabelled block
    #     that still fingerprinted the machine as "runs a blocker". Loopback
    #     only (DeceptionEndpoint enforces this in its constructor); a failed
    #     bind (port in use) leaves `deception` None and DNSInterceptor falls
    #     back to the sinkhole exactly as before — this can only ever improve
    #     on the old behaviour, never regress it. See deception.py / persona.py.
    # ------------------------------------------------------------------
    _t = time.monotonic()
    deception = None
    if not args.no_dns:
        from .config import DECEPTION_PORT
        from .deception import DeceptionEndpoint
        deception = DeceptionEndpoint(port=DECEPTION_PORT)
        if deception.start():
            _tick(f"Deception endpoint listening on 127.0.0.1:{DECEPTION_PORT}", _t)
        else:
            console.print(f"[dim]Deception endpoint unavailable (port "
                          f"{DECEPTION_PORT} in use) — DECEIVE falls back to "
                          f"the sinkhole[/dim]")
            deception = None

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
            intelligence    = intelligence,
            firewall        = (firewall if not args.no_firewall else None),
            threat_intel    = threat_intel,
            content_watch   = content_watch,
            deception       = deception,
            strict          = args.strict,
            host            = args.host,
            port            = args.port,
            upstream_host   = dns_upstream_host,
            upstream_port   = dns_upstream_port,
            allow_external_fallback = allow_external_fallback,
            # Zero-log forces per-domain stdout off: the interceptor's debug
            # prints include every queried domain, which would persist in
            # terminal scrollback and defeat RAM-only operation.
            debug           = args.debug and not (zero_log is not None and zero_log.is_active()),
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
        # store.build_baselines() does substantial SQLite work and can raise
        # (locked database, disk full, a schema surprise). Unguarded, the first
        # such failure killed this thread and baselines were never rebuilt again
        # for the life of the process — the anomaly detector would keep scoring
        # against an ageing baseline while everything looked normal.
        while True:
            time.sleep(3600)    # check every hour
            try:
                if store.should_build_baseline():
                    store.build_baselines()
            except BaseException as exc:      # noqa: BLE001
                console.print(f"[yellow]Baseline rebuild failed ({exc}); "
                              f"will retry next hour.[/yellow]")

    if args.build_baseline:
        if store.should_build_baseline():
            store.build_baselines()
            console.print("[green]✓[/green] Baselines rebuilt.")
        else:
            console.print("[yellow]Not enough data yet — need 24h of events.[/yellow]")
    else:
        threading.Thread(target=_baseline_loop, daemon=True, name="baseline").start()

    # ------------------------------------------------------------------
    # 9b. Protection heartbeat — continuously re-verify the sinkhole answers
    # ------------------------------------------------------------------
    heartbeat = None
    if dns_server is not None:
        from .self_test import HeartbeatMonitor

        def _on_health_change(healthy: bool) -> None:
            if healthy:
                console.print("[green]✓ Protection heartbeat recovered — DNS sinkhole answering again.[/green]")
            else:
                console.print("[bold red]⚠ PROTECTION HEARTBEAT FAILED — DNS sinkhole is not answering![/bold red]")

        heartbeat = HeartbeatMonitor(
            dns_host  = args.host,
            dns_port  = args.port,
            interval  = 15.0,
            store     = store,
            on_change = _on_health_change,
        )
        heartbeat.start()

    # ------------------------------------------------------------------
    # 9c. EDR layer — detection → incident → response on top of the sensors.
    #     Subscribes to the live event stream and correlates detections into
    #     incidents. Stays entirely local (state lives in the same DB).
    # ------------------------------------------------------------------
    edr_engine = None
    siem_exporter = None
    playbook_engine = None
    sensor_manager = None
    process_collector = None
    network_collector = None
    persistence_collector = None
    cred_watch = None
    sensor_tamper_monitor = None
    amsi_scanner = None
    from .config import EDR_MODE, EDR_CORRELATION_WINDOW, EDR_PLUGIN_DIR
    if EDR_MODE and not args.no_edr:
        _t = time.monotonic()
        from .edr import EdrEngine
        plugin_dir = args.edr_plugin_dir or (str(EDR_PLUGIN_DIR) if EDR_PLUGIN_DIR.exists() else "")
        edr_engine = EdrEngine(
            store,
            intelligence = intelligence,
            firewall     = firewall,
            rules        = rules,
            blocklist    = blocklist,
            plugin_dir   = plugin_dir,
            correlation_window_seconds = EDR_CORRELATION_WINDOW,
        )
        edr_engine.start()
        _pi = edr_engine.plugins()
        _tick(f"EDR active ({len(_pi['plugins'])} plugins, "
              f"{len(_pi['actions'])} response actions)", _t)

        # SIEM export (opt-in): stream incidents (and, with --siem-dns, DNS
        # blocks) to the operator's log pipeline in CEF or JSON Lines. The
        # exporter is queue-buffered and reconnecting — SIEM downtime never
        # touches the protection pipeline.
        if args.siem:
            _ts = time.monotonic()
            from .siem import SiemExporter
            try:
                siem_exporter = SiemExporter(args.siem, fmt=args.siem_format)
                siem_exporter.start()
                edr_engine.subscribe(siem_exporter.export_incident)
                if args.siem_dns:
                    store.subscribe(siem_exporter.export_dns)
                _tick(f"SIEM export active ({args.siem_format} → {args.siem})", _ts)
            except ValueError as exc:
                console.print(f"[red]SIEM export disabled: {exc}[/red]")
                siem_exporter = None

        # SOAR playbooks: analyst-authored YAML mapping incident conditions
        # onto the audited response actions. Dry-run unless a playbook says
        # 'mode: enforce'; idle when data/playbooks.yaml doesn't exist.
        from .edr.playbooks import PlaybookEngine
        playbook_engine = PlaybookEngine(edr_engine)
        n_pb = playbook_engine.load()
        if n_pb:
            playbook_engine.start()
            _tick(f"SOAR playbooks active ({n_pb})", _t)

        # Endpoint telemetry + real-time sensors are ON BY DEFAULT so a shipped
        # install actually protects the endpoint however it was launched — a
        # launch script that forgets to pass --endpoint must NOT silently drop
        # the client to DNS-only (no process/persistence detection, no
        # command-line sensor). Pass --no-endpoint for explicit DNS-only. (This
        # whole block is already inside the EDR-enabled path, so --no-edr still
        # disables it.)
        endpoint_enabled = not getattr(args, "no_endpoint", False)
        if endpoint_enabled:
            _tp = time.monotonic()
            from .process_telemetry import ProcessCollector
            process_collector = ProcessCollector(
                emit=lambda ev: edr_engine.ingest_telemetry(ev))
            if process_collector.available():
                process_collector.start()
                _tick("Endpoint telemetry active (process collector)", _tp)
            else:
                process_collector = None
                console.print("[yellow]Endpoint telemetry unavailable "
                              "(psutil not installed)[/yellow]")

            # Network connection telemetry: flag outbound connections to
            # threat-intel IPs — the hard-coded-IP C2 case DNS never sees (and
            # that the Windows in-process firewall does not block). Reuses the
            # firewall's is_blocked_ip reputation set.
            _tn = time.monotonic()
            from .network_telemetry import NetworkCollector
            # Reputation = firewall CIDR ranges OR threat-intel C2 IPs; either
            # source flags the connection into the same incident pipeline.
            def _ip_bad(ip: str) -> bool:
                if firewall is not None and firewall.is_blocked_ip(ip):
                    return True
                return threat_intel.match_ip(ip) is not None
            network_collector = NetworkCollector(
                emit=lambda ev: edr_engine.ingest_telemetry(ev),
                ip_reputation=_ip_bad)
            if network_collector.available():
                network_collector.start()
                _tick("Endpoint telemetry active (network collector)", _tn)
            else:
                network_collector = None

            # Persistence (ASEP) telemetry: registry Run keys, services,
            # scheduled tasks, startup folders → the same correlation pipeline.
            _tpr = time.monotonic()
            from .persistence_telemetry import PersistenceCollector
            persistence_collector = PersistenceCollector(
                emit=lambda ev: edr_engine.ingest_telemetry(ev))
            if persistence_collector.available():
                persistence_collector.start()
                _tick("Endpoint telemetry active (persistence collector)", _tpr)
            else:
                persistence_collector = None

            # Browser credential-store watch: flags any non-browser process
            # holding a handle open to Chrome/Edge/Brave/Firefox's own saved-
            # password store (T1555.003) — a userland poll of open file
            # handles, the same honest boundary as every other sensor here
            # (real-time capture needs the kernel driver, see docs/adr/0026).
            _tcw = time.monotonic()
            from .browser_cred_watch import CredentialStoreWatch
            cred_watch = CredentialStoreWatch(
                emit=lambda ev: edr_engine.ingest_telemetry(ev))
            if cred_watch.available():
                cred_watch.start()
                _tick("Endpoint telemetry active (browser credential-store watch)", _tcw)
            else:
                cred_watch = None

            # Sensor tamper detection (ADR 0048) — nothing previously noticed
            # when Valkyrie's OWN sensors went dark. Watches Sysmon health
            # (present / running / collection actually live / expected EIDs
            # still configured) and raises a CRITICAL T1562.001 incident the
            # moment a previously-healthy sensor stops delivering, instead of
            # silently degrading with no signal at all.
            _tst = time.monotonic()
            from .sensor_tamper import SensorTamperMonitor
            # Compensating control (valkyrie/control_taxonomy.py, IIBA §4.2.3):
            # when Sysmon dies, actively tighten the independent psutil-based
            # process poller instead of silently continuing at its normal
            # cadence. Partial coverage only — see control_taxonomy.py for
            # exactly what this does and does not substitute for.
            _sysmon_compensations = {}
            if process_collector is not None:
                _sysmon_compensations["sysmon"] = (
                    lambda: process_collector.tighten(4.0),
                    process_collector.restore_interval,
                )
            sensor_tamper_monitor = SensorTamperMonitor(
                emit=lambda ev: edr_engine.ingest_telemetry(ev),
                compensations=_sysmon_compensations)
            sensor_tamper_monitor.start()
            _tick("Sensor tamper detection active", _tst)

            # Real-time ETW-backed sensors (PowerShell script-block today; more
            # channels next) hosted by the resilient SensorManager — watchdog,
            # de-dup, and bounded backpressure. Emits into the SAME EDR pipeline.
            # AMSI content scanning — a real verdict from the OS antimalware
            # provider for the script text the PowerShell sensor captures.
            # Valkyrie ships no signature engine; this asks the engine that
            # already has one. Self-disables when no provider is present, so a
            # failure here costs the corroborator, never the sensor.
            from .config import (AMSI_ENABLED, AMSI_SCAN_SCRIPTS,
                                 AMSI_MAX_BYTES, AMSI_CACHE_SIZE)
            if AMSI_ENABLED and not getattr(args, "no_amsi", False):
                _ta = time.monotonic()
                from .amsi import AmsiScanner
                _a = AmsiScanner(enabled=True, max_bytes=AMSI_MAX_BYTES,
                                 cache_size=AMSI_CACHE_SIZE)
                try:
                    if _a.start():
                        amsi_scanner = _a
                        _state = _a.provider_state()
                        _tick(f"AMSI content scanning active (provider: {_state})", _ta)
                        if _state != "resident":
                            console.print(
                                "[yellow]AMSI: no antimalware provider is resident — "
                                "scans will return 'not detected' regardless of "
                                "content until one is installed.[/yellow]")
                except Exception as _e:      # never block startup
                    console.print(f"[yellow]AMSI unavailable: {_e}[/yellow]")
                    amsi_scanner = None

            _ts = time.monotonic()
            from .etw import (SensorManager, PowerShellSensor, WmiActivitySensor,
                              SysmonSensor, NativeProcessSensor)
            sensor_manager = SensorManager(sink=lambda ev: edr_engine.ingest_telemetry(ev))
            sensor_manager.register(PowerShellSensor(
                scanner=amsi_scanner if AMSI_SCAN_SCRIPTS else None))
            sensor_manager.register(WmiActivitySensor())
            _sysmon = SysmonSensor()
            sensor_manager.register(_sysmon)          # optional; skipped if absent
            # Native process-creation sensor: gives command-line detection from
            # Windows' own Security/4688 events, so a normal user gets the good
            # detection path with NOTHING to install. Stands down when Sysmon is
            # present (Sysmon is the richer source), so the two never double-
            # report. Best-effort enables 4688+cmdline auditing when we have the
            # privilege; if it can't, the sensor simply reports unavailable and
            # the engine falls back to the poller exactly as before.
            try:
                from . import native_audit
                _en_ok, _en_detail = native_audit.enable_process_auditing()
                console.print(f"[dim]  Native process auditing: {_en_detail}[/dim]")
            except Exception as _exc:      # noqa: BLE001
                console.print(f"[dim]  Native process auditing: unavailable ({_exc})[/dim]")
            sensor_manager.register(
                NativeProcessSensor(suppress_when=_sysmon.available))
            # Kernel driver bridge — authoritative process lineage + LSASS
            # credential-theft protection when the signed driver is loaded;
            # self-disables (available()==False) otherwise, so this is safe to
            # register unconditionally. See driver/valkyrie_km + ADR 0026.
            from .kernel_bridge import KernelSensor
            sensor_manager.register(KernelSensor())
            if sensor_manager.start() > 0:
                _tick(f"Real-time sensors active ({', '.join(sensor_manager.active_sensors())})", _ts)
            else:
                sensor_manager.stop()
                sensor_manager = None
    elif args.debug:
        console.print("[yellow]EDR layer disabled (--no-edr)[/yellow]")

    # ------------------------------------------------------------------
    # 9d. Ransomware Shield — behavioral, local. Plants canary tripwires,
    #     confirms encryption by entropy, attributes the writer by disk I/O and
    #     suspends it, raising a CRITICAL incident through the EDR pipeline.
    # ------------------------------------------------------------------
    ransomware_shield = None
    from .config import (RANSOMWARE_SHIELD_ENABLED, RANSOMWARE_RESPONSE_MODE,
                         RANSOMWARE_POLL_INTERVAL, RANSOMWARE_MANIFEST_PATH)
    if RANSOMWARE_SHIELD_ENABLED and not getattr(args, "no_ransomware_shield", False):
        _t = time.monotonic()
        from .ransomware_shield import RansomwareShield
        ransomware_shield = RansomwareShield(
            manifest_path = RANSOMWARE_MANIFEST_PATH,
            edr           = edr_engine,
            store         = store,
            response_mode = RANSOMWARE_RESPONSE_MODE,
            poll_interval = RANSOMWARE_POLL_INTERVAL,
        )
        try:
            armed = ransomware_shield.start()
            _tick(f"Ransomware shield armed ({ransomware_shield.stats['canaries']} canaries, "
                  f"mode={RANSOMWARE_RESPONSE_MODE})", _t)
            if not armed:
                console.print("[yellow]Ransomware shield: no canaries could be placed "
                              "(no writable user folders?)[/yellow]")
        except Exception as _e:   # never let it block startup
            console.print(f"[yellow]Ransomware shield unavailable: {_e}[/yellow]")
            ransomware_shield = None

    # ------------------------------------------------------------------
    # 9e. Decoy honeytokens — fake passwords / keys / "confidential" files an
    #     intruder browsing the box will trip. Detection reuses the command-line
    #     eye: any process referencing a decoy is, by construction, recon — the
    #     engine forces it CRITICAL + labels it 'decoy' (see edr/engine.py) and
    #     the decision policy routes it to CONTAIN. Only when endpoint sensors
    #     are active (nothing sees the command line otherwise).
    # ------------------------------------------------------------------
    if edr_engine is not None:
        _t = time.monotonic()
        try:
            from .decoys import DecoyManager, set_active
            from .config import DATA_DIR
            _decoys = DecoyManager(manifest_path=DATA_DIR / "decoys.json")
            _decoys.load()
            _n = _decoys.deploy()
            set_active(_decoys)
            _tick(f"Decoy honeytokens planted ({len(_decoys.tokens())} tripwires)", _t)
        except Exception as _e:   # never block startup
            console.print(f"[dim]Decoys unavailable ({_e})[/dim]")

    # ------------------------------------------------------------------
    # 9e. Component registry — the uniform plugin contract over every
    #     subsystem (register/health/metrics/config/restart/events). It
    #     ADAPTS the services built above; nothing is rewritten. See
    #     docs/adr/0021-component-registry.md.
    # ------------------------------------------------------------------
    from .components import ComponentRegistry
    from .eventbus import EventBus
    registry = ComponentRegistry(bus=EventBus("components"))
    _reg_specs = [
        ("store", store, "storage"),
        ("firewall", firewall, "network"),
        ("blocklist", blocklist, "network"),
        ("threat_intel", threat_intel, "intelligence"),
        ("intelligence", intelligence, "detection"),
        ("edr", edr_engine, "detection"),
        ("sensor_manager", sensor_manager, "sensor"),
        ("process_collector", process_collector, "sensor"),
        ("network_collector", network_collector, "sensor"),
        ("persistence_collector", persistence_collector, "sensor"),
        ("cred_watch", cred_watch, "sensor"),
        ("amsi", amsi_scanner, "detection"),
        ("ransomware_shield", ransomware_shield, "response"),
        ("siem", siem_exporter, "integration"),
        ("playbooks", playbook_engine, "response"),
        ("mac_randomizer", mac_randomizer, "privacy"),
        ("zero_log", zero_log, "privacy"),
        ("content_watch", content_watch, "detection"),
        ("process_watcher", proc_watcher, "sensor"),
    ]
    for _cname, _csvc, _ckind in _reg_specs:
        if _csvc is not None:
            registry.register_service(_cname, _csvc, kind=_ckind)
    _tick(f"Component registry ({len(registry.names())} plugins)", time.monotonic())

    # ------------------------------------------------------------------
    # 10. Web dashboard (optional)
    # ------------------------------------------------------------------
    web_thread = None
    web_state = None
    if args.web:
        from .web.server import run_server
        from .context import AppContext
        # __main__ is the composition root: build the context, wire services in,
        # and inject it into the web server (create_app/run_server), rather than
        # mutating a module-global singleton.
        web_state = AppContext(
            store          = store,
            firewall       = firewall,
            blocklist      = blocklist,
            start_time     = time.time(),
            mac_randomizer = mac_randomizer,
            zero_log       = zero_log,
            dns_port       = args.port,
            web_port       = args.web_port,
            intelligence   = intelligence,
            edr            = edr_engine,
            process_collector = process_collector,
            network_collector = network_collector,
            persistence_collector = persistence_collector,
            cred_watch      = cred_watch,
            sensor_manager = sensor_manager,
            heartbeat      = heartbeat,
            ransomware_shield = ransomware_shield,
            threat_intel   = threat_intel,
            siem           = siem_exporter,
            playbooks      = playbook_engine,
            registry       = registry,
            amsi           = amsi_scanner,
            content_watch  = content_watch,
            doh            = doh,
            # tls_inspector is created further down (it needs the store and a
            # started engine), so it is attached to the context after start()
            # rather than here — see the assignment below.
        )
        if args.web_host not in ("127.0.0.1", "::1", "localhost"):
            console.print(
                f"[yellow]⚠ Web dashboard bound to {args.web_host} (off-loopback).[/yellow]\n"
                f"  Live DNS/browsing history is reachable from the network. "
                f"Off-loopback API and WebSocket calls now require the control "
                f"token in [cyan]data/control_token.txt[/cyan] "
                f"(header X-Valkyrie-Token or ?token=…)."
            )
        web_thread = threading.Thread(
            target=run_server,
            kwargs={"host": args.web_host, "port": args.web_port, "ctx": web_state},
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
    # 10b. Self-healing watchdog — checks components every 30s, attempts
    #      recovery on failure, isolates faults so nothing takes the
    #      whole system down.
    # ------------------------------------------------------------------
    healer = None
    if intelligence is not None:
        from .intelligence import SelfHealing
        healer = SelfHealing(store=store)

        if dns_server is not None:
            def _recover_dns() -> None:
                try:
                    dns_server.stop()
                except Exception:
                    pass
                dns_server.start()
            healer.register("dns_interceptor", dns_server.is_listening, _recover_dns)

        # store.restart_writer is the RECOVERY action. Without it the watchdog
        # could detect a dead event writer and do nothing — which is what it
        # did, while every DNS decision, detection and response went unrecorded.
        healer.register("store_writer", store.is_writing, store.restart_writer)

        if args.web:
            def _check_web() -> bool:
                import urllib.request
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{args.web_port}/api/stats", timeout=3
                    ) as resp:
                        return resp.status == 200
                except Exception:
                    return False
            healer.register("web_dashboard", _check_web)

        if unbound_ok and unbound is not None:
            def _check_unbound() -> bool:
                import socket as _s
                host, port = unbound.upstream_addr()
                probe = (b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                         b"\x07example\x03com\x00\x00\x01\x00\x01")
                sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
                try:
                    sock.settimeout(2.0)
                    sock.sendto(probe, (host, port))
                    sock.recvfrom(512)
                    return True
                except OSError:
                    return False
                finally:
                    sock.close()

            def _recover_unbound() -> None:
                unbound.start()

            healer.register("unbound", _check_unbound, _recover_unbound)

        # Ransomware shield: if the monitor thread dies, restart it (re-arming
        # canaries), so protection self-heals like every other subsystem.
        if ransomware_shield is not None:
            healer.register("ransomware_shield",
                            ransomware_shield.is_running,
                            ransomware_shield.start)

        # Real-time sensor host: the manager has an internal per-sensor watchdog,
        # and the global self-heal loop restarts the whole manager if it dies.
        if sensor_manager is not None:
            healer.register("sensor_manager",
                            sensor_manager.is_healthy,
                            sensor_manager.start)

        # Page-content analysis: a dead worker would leave the feature looking
        # enabled while analysing nothing, which is precisely the silent-failure
        # class this project keeps finding. Watch it like everything else.
        if content_watch is not None:
            healer.register("content_watch",
                            content_watch.is_running,
                            content_watch.start)

        # Process attribution. Its refresh thread used to die on any single
        # psutil/OS exception, freezing the port->process table and making every
        # subsequent DNS event attribute to whatever process held that port at
        # the moment of death — wrong attribution, reported as fact, forever.
        # is_running() now covers both "thread alive" and "table not stale", so
        # the watchdog can catch either failure.
        if proc_watcher is not None:
            healer.register("process_watcher",
                            proc_watcher.is_running,
                            proc_watcher.start)

        healer.start()
        if args.web:
            web_state.self_heal = healer

    # ------------------------------------------------------------------
    # 11. TLS inspection (optional — disabled by default)
    # ------------------------------------------------------------------
    tls_inspector = None
    if args.tls and not args.no_tls:
        from .tls_inspector import TLSInspector
        tls_inspector = TLSInspector(store=store, blocklist=blocklist, behavioral=behavioral,
                                     rules=rules, threat_intel=threat_intel)
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

    # Attach to the dashboard context only if it actually started. /api/stats
    # keys the "Trackers Cleaned" counter off this: when TLS inspection is not
    # running, nothing can ever write a page_clean row, so the API reports null
    # (rendered as "off") instead of a 0 that looks like a live-but-idle count.
    if web_state is not None:
        web_state.tls_inspector = tls_inspector
        web_state.sensor_tamper = sensor_tamper_monitor

    # ------------------------------------------------------------------
    # 12. Startup status box (real values) + auto-open dashboard
    # ------------------------------------------------------------------
    status_rows = build_status_rows(
        args=args, dns_server=dns_server, firewall=firewall,
        edr_engine=edr_engine, intelligence=intelligence,
        unbound_ok=unbound_ok, dns_upstream_host=dns_upstream_host,
        dns_upstream_port=dns_upstream_port,
        allow_external_fallback=allow_external_fallback, zero_log=zero_log,
        mac_randomizer=mac_randomizer, tls_inspector=tls_inspector,
        heartbeat=heartbeat, sysmon_result=sysmon_result,
    )
    web_url = f"http://localhost:{args.web_port}"

    _print_status_box(console, status_rows)

    console.print()
    if protection_state(status_rows) == "ACTIVE":
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
        if heartbeat:
            heartbeat.stop()
        if dns_server:
            dns_server.stop()
        if unbound:
            unbound.stop()
        if tls_inspector:
            tls_inspector.stop()
        if mac_randomizer:
            mac_randomizer.stop()
        if healer:
            healer.stop()
        # Stopped after the healer, so its recovery hook cannot restart the
        # worker we are in the middle of shutting down.
        if content_watch is not None:
            content_watch.stop()
        if deception is not None:
            deception.stop()
        if persistence_collector is not None:
            persistence_collector.stop()
        if cred_watch is not None:
            cred_watch.stop()
        if sensor_tamper_monitor is not None:
            sensor_tamper_monitor.stop()
        if sensor_manager is not None:
            sensor_manager.stop()
        # After the sensors that use it, so no scan is in flight at teardown.
        if amsi_scanner is not None:
            amsi_scanner.stop()
        if ransomware_shield is not None:
            ransomware_shield.stop()
        if playbook_engine is not None:
            playbook_engine.stop()
        if siem_exporter is not None:
            siem_exporter.stop()
        if edr_engine is not None:
            edr_engine.stop()
        if intelligence:
            intelligence.stop()
        if threat_intel is not None:
            threat_intel.stop()
        firewall.stop()
        # zero_log.disable() must run BEFORE store.stop(): its secure wipe
        # deletes rows through a fresh connection to the shared-cache RAM
        # database, which only works while another connection (the Store's
        # writer thread) is still open. `file::memory:?cache=shared` DBs are
        # destroyed the instant their last connection closes, so wiping
        # after store.stop() would silently target an already-gone database
        # (see docs/TLS_ZEROLOG_AUDIT_REPORT.md).
        if zero_log:
            zero_log.disable()
        store.stop()
        console.print("[green]Done.[/green]")


if __name__ == "__main__":
    main()
