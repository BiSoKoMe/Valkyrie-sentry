"""Application context — the composition root's service container.

Holds the shared, long-lived services that are wired together once at startup.
Passing this single object explicitly (constructor/parameter injection) is the
Pythonic middle ground between a pile of positional arguments and a heavyweight
DI framework: consumers receive exactly the context they need, and a test can
build an isolated one instead of mutating a process-global singleton.

Every service is Optional and defaults to None. Many are enabled only by a flag
(``--web``, ``--tls``, ``--mac-rand``, EDR, the self-heal watchdog), so "not
wired" is a first-class state that the dashboard and health checks already
handle — ``components()`` reports exactly what is present.

This replaces the anonymous ``_AppState`` bag that previously lived inside
``web/server.py``: same fields, but a documented, typed, reusable type that the
startup path (`__main__`) constructs and injects rather than reaching into a
module global.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Service attributes are typed as Optional[object] rather than importing the
# concrete classes: this module sits at the root of the wiring graph, and
# importing store/firewall/edr/etc. here would create import cycles. The
# comments name the concrete type each field holds.


@dataclass
class AppContext:
    """Container for the shared services assembled at startup."""

    store:          Optional[object] = None   # valkyrie.store.Store
    firewall:       Optional[object] = None   # valkyrie.firewall.FirewallManager
    blocklist:      Optional[object] = None   # valkyrie.blocklist.BlocklistManager
    intelligence:   Optional[object] = None   # valkyrie.intelligence.Intelligence
    edr:            Optional[object] = None   # valkyrie.edr.EdrEngine
    mac_randomizer: Optional[object] = None   # valkyrie.mac_randomizer.MacRandomizer
    zero_log:       Optional[object] = None   # valkyrie.zero_log.ZeroLogMode
    self_heal:      Optional[object] = None   # valkyrie.intelligence.SelfHealing
    process_collector: Optional[object] = None  # valkyrie.process_telemetry.ProcessCollector
    network_collector: Optional[object] = None  # valkyrie.network_telemetry.NetworkCollector
    sensor_manager:    Optional[object] = None  # valkyrie.etw.SensorManager (real-time sensors)
    persistence_collector: Optional[object] = None  # valkyrie.persistence_telemetry.PersistenceCollector
    heartbeat:      Optional[object] = None   # valkyrie.self_test.HeartbeatMonitor
    ransomware_shield: Optional[object] = None  # valkyrie.ransomware_shield.RansomwareShield
    threat_intel:   Optional[object] = None   # valkyrie.threat_intel.ThreatIntelManager

    start_time: float = 0.0
    dns_port:   int   = 0     # actual DNS listen port (for dashboard display)
    web_port:   int   = 0     # actual web dashboard port

    # Names of the optional service fields, in a stable order for introspection.
    _SERVICES = (
        "store", "firewall", "blocklist", "intelligence", "edr",
        "mac_randomizer", "zero_log", "self_heal", "process_collector",
        "network_collector", "persistence_collector", "sensor_manager",
        "heartbeat", "ransomware_shield", "threat_intel",
    )

    def components(self) -> dict[str, bool]:
        """Return {service_name: is_wired} for every optional service.

        A small, honest health/inventory view used by callers that want to know
        what is actually running in this deployment without poking at each field.
        """
        return {name: getattr(self, name) is not None for name in self._SERVICES}

    def __repr__(self) -> str:
        wired = [n for n in self._SERVICES if getattr(self, n) is not None]
        return f"<AppContext wired={wired} web_port={self.web_port}>"
