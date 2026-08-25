"""Rich terminal dashboard.

Layout:
  ┌--- header ---┐
  │  stat cards (total / blocked / flagged / allowed) │
  ├--- recent events table ---┤
  │  scrolling live feed of the last N DNS decisions  │
  ├--- DoH alerts ---┤
  │  any DoH bypass events logged in this session     │
  └--- status bar ---┘

All rendering happens on the main thread via Rich's Live context.
The Store read API is called at UI_REFRESH_RATE Hz.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Optional

from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .config import UI_MAX_TABLE_ROWS, UI_REFRESH_RATE
from .firewall import FirewallManager
from .store import Store

# Decision -> colour mapping
_DECISION_STYLE = {
    "blocked":    "bold red",
    "behavioral": "bold magenta",
    "flagged":    "bold yellow",
    "allowed":    "green",
}


def _decision_text(decision: str) -> Text:
    style = _DECISION_STYLE.get(decision, "white")
    return Text(decision.upper(), style=style)


def _stat_panel(label: str, value: str, color: str = "cyan") -> Panel:
    return Panel(
        Align.center(Text(value, style=f"bold {color}", justify="center")),
        title=f"[dim]{label}[/dim]",
        border_style=color,
        padding=(0, 2),
    )


class Dashboard:
    """Rich live dashboard.  Call .run() to block; or .start() for background."""

    def __init__(
        self,
        store: Store,
        console: Optional[Console] = None,
        firewall: Optional[FirewallManager] = None,
    ) -> None:
        self._store    = store
        self._console  = console or Console()
        self._firewall = firewall
        self._doh_alerts: list[dict] = []
        self._doh_lock  = threading.Lock()
        self._running   = False
        self._render_errors = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Run dashboard in a background thread."""
        self._running = True
        t = threading.Thread(target=self.run, daemon=True, name="ui")
        t.start()

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        """Block and render until Ctrl-C."""
        self._running = True
        with Live(
            self._build_layout(),
            console    = self._console,
            refresh_per_second = UI_REFRESH_RATE,
            screen     = True,
        ) as live:
            # _build_layout() reads live state from the store and every
            # subsystem, so a transient error there (a closed DB handle during
            # shutdown, a subsystem mid-restart) could raise. Unguarded, that
            # killed the render thread and the terminal dashboard froze on its
            # last frame - still showing numbers, no longer updating, with no
            # indication the display had stopped.
            while self._running:
                try:
                    live.update(self._build_layout())
                except BaseException:         # noqa: BLE001
                    self._render_errors += 1
                time.sleep(1.0 / UI_REFRESH_RATE)

    def push_doh_alert(self, process_name: str, remote_ip: str, pid: int) -> None:
        """Called from DoHDetector when a bypass is detected."""
        with self._doh_lock:
            self._doh_alerts.append({
                "ts":      datetime.utcnow().strftime("%H:%M:%S"),
                "process": process_name,
                "ip":      remote_ip,
                "pid":     pid,
            })
            # Keep last 20
            self._doh_alerts = self._doh_alerts[-20:]

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _build_layout(self) -> Layout:
        stats  = self._store.stats()
        events = self._store.recent_events(limit=UI_MAX_TABLE_ROWS)

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="stats",  size=5),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="events", ratio=3),
            Layout(name="side",   ratio=1),
        )

        layout["header"].update(self._header())
        layout["stats"].update(self._stats_row(stats))
        layout["events"].update(self._events_table(events))
        layout["side"].update(self._doh_panel())
        layout["footer"].update(self._footer(stats))
        return layout

    def _header(self) -> Panel:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        return Panel(
            Align.center(Text("⚡  VALKYRIE  —  Privacy Gateway", style="bold white")),
            subtitle=f"[dim]{ts}[/dim]",
            border_style="bright_blue",
        )

    def _stats_row(self, stats: dict) -> Columns:
        fw_count = str(self._firewall.count()) if self._firewall else "off"
        return Columns([
            _stat_panel("Total (24h)",  str(stats["total_24h"]),   "cyan"),
            _stat_panel("DNS Blocked",  str(stats["blocked_24h"]), "red"),
            _stat_panel("FW Blocked",   fw_count,                  "bright_red"),
            _stat_panel("Flagged",      str(stats["flagged_24h"]), "yellow"),
            _stat_panel("Allowed",      str(stats["allowed_24h"]), "green"),
            _stat_panel("Top Domain",   stats["top_domain"],       "bright_blue"),
            _stat_panel("Top Process",  stats["top_process"],      "magenta"),
        ], equal=True, expand=True)

    def _events_table(self, events: list[dict]) -> Panel:
        table = Table(
            show_header  = True,
            header_style = "bold bright_blue",
            expand       = True,
            show_lines   = False,
            padding      = (0, 1),
        )
        table.add_column("Time",     style="dim",    width=10, no_wrap=True)
        table.add_column("Decision", width=12, no_wrap=True)
        table.add_column("Domain",   style="white",  ratio=3,  no_wrap=True, overflow="ellipsis")
        table.add_column("Process",  style="cyan",   ratio=1,  no_wrap=True, overflow="ellipsis")
        table.add_column("Reason",   style="dim",    ratio=2,  no_wrap=True, overflow="ellipsis")
        table.add_column("Score",    width=6,        no_wrap=True)

        for ev in events:
            ts_str = ev.get("timestamp", "")[:19].replace("T", " ")[11:]  # HH:MM:SS
            score  = ev.get("suspicion", 0.0)
            score_style = "red" if score >= 0.7 else ("yellow" if score >= 0.4 else "dim")
            table.add_row(
                ts_str,
                _decision_text(ev.get("decision", "")),
                ev.get("domain", ""),
                ev.get("process_name", ""),
                ev.get("reason", ""),
                Text(f"{score:.2f}", style=score_style),
            )

        return Panel(table, title="[bold]Live DNS Events[/bold]", border_style="bright_blue")

    def _doh_panel(self) -> Panel:
        with self._doh_lock:
            alerts = list(self._doh_alerts)

        if not alerts:
            body = Text("No DoH bypass detected.", style="dim")
        else:
            lines = []
            for a in reversed(alerts[-10:]):
                lines.append(
                    Text.assemble(
                        (a["ts"],      "dim"),
                        "  ",
                        (a["process"], "bold yellow"),
                        " → ",
                        (a["ip"],      "red"),
                    )
                )
            body = Text("\n").join(lines)

        return Panel(
            body,
            title="[bold red]DoH Bypass Alerts[/bold red]",
            border_style="red",
        )

    def _footer(self, stats: dict) -> Panel:
        msg = Text.assemble(
            ("DNS port: ", "dim"), (str(5353), "cyan"),
            "  │  ",
            ("Press ", "dim"), ("Ctrl-C", "bold"), (" to exit", "dim"),
        )
        return Panel(Align.center(msg), border_style="dim")
