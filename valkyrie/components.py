"""Component platform — the uniform plugin contract over every subsystem.

Valkyrie's subsystems (DNS, firewall, threat-intel, SIEM, EDR, sensors,
ransomware shield, playbooks, …) each already have lifecycle and their own
ad-hoc ``status()``/``stats()`` shape. This module gives them ONE contract
without rewriting any of them:

    register → health → metrics → config → restart → events

A :class:`Component` is a thin *adapter* around an existing service object.
It introspects the service for the methods it already has
(``available``/``is_healthy``/``is_running``/``status``/``stats``/
``start``/``stop``) and presents a normalized surface. Nothing about the
wrapped service changes — this is composition, not inheritance, so it never
duplicates a detection engine, database, or API.

The :class:`ComponentRegistry` is the plugin host:

  * **Fault isolation** — a component whose ``health()``/``metrics()`` raises
    is reported as ``error`` state; it can never crash the registry or the
    engine (the same guarantee the EventBus gives subscribers).
  * **Event-driven** — health-state transitions publish a ``component`` event
    onto the shared EventBus, so the dashboard/WebSocket and any future
    correlation can react to a subsystem degrading in real time.
  * **Independent restart** — ``restart(name)`` stops and starts a single
    component without touching the others (used by the API and, optionally,
    by the self-heal watchdog as its recover action).
  * **Uniform observability** — ``snapshot()`` returns every component's
    kind, health, metrics, and config in one shape for ``/api/components``.

This is the seam the platform vision (docs/ARCHITECTURE.md) calls the plugin
registry: every capability registers itself and exposes health/metrics/
config/events and restarts independently, all over the existing EventBus.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# Health states, ordered worst→best for aggregation.
STATE_ERROR = "error"        # health probe itself raised — unknown/bad
STATE_DOWN = "down"          # wired but not running/healthy
STATE_DEGRADED = "degraded"  # running but self-reported unhealthy
STATE_DISABLED = "disabled"  # not applicable on this host (available()==False)
STATE_UP = "up"              # running and healthy
_STATE_RANK = {STATE_ERROR: 0, STATE_DOWN: 1, STATE_DEGRADED: 2,
               STATE_DISABLED: 3, STATE_UP: 4}


@dataclass
class Health:
    state: str
    detail: str = ""
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"state": self.state, "detail": self.detail,
                "checked_at": self.checked_at}


class Component:
    """Uniform contract over one subsystem, adapting an existing service.

    Args:
        name: stable component id (matches AppContext field names where possible).
        service: the wrapped object (may be None → reported ``down``).
        kind: category for the UI ("sensor", "network", "detection", …).
        health_fn/metrics_fn/config_fn: optional overrides; when absent the
            adapter introspects the service.
        restartable: force restart capability on/off; None = auto-detect
            (service exposes both ``start`` and ``stop``).
    """

    def __init__(self, name: str, service: object, *, kind: str = "service",
                 health_fn: Optional[Callable[[], Health]] = None,
                 metrics_fn: Optional[Callable[[], dict]] = None,
                 config_fn: Optional[Callable[[], dict]] = None,
                 restartable: Optional[bool] = None) -> None:
        self.name = name
        self.kind = kind
        self._service = service
        self._health_fn = health_fn
        self._metrics_fn = metrics_fn
        self._config_fn = config_fn
        if restartable is None:
            restartable = (service is not None
                           and callable(getattr(service, "start", None))
                           and callable(getattr(service, "stop", None)))
        self.restartable = restartable

    # ------------------------------------------------------------------
    # Health (never raises — the registry relies on this)
    # ------------------------------------------------------------------

    def health(self) -> Health:
        try:
            return self._probe_health()
        except Exception as exc:   # noqa: BLE001 — a bad probe is a health signal
            return Health(STATE_ERROR, f"{type(exc).__name__}: {exc}")

    def _probe_health(self) -> Health:
        svc = self._service
        if svc is None:
            return Health(STATE_DOWN, "not wired")
        if self._health_fn is not None:
            return self._health_fn()
        # available() == False → the subsystem doesn't apply on this host.
        avail = getattr(svc, "available", None)
        if callable(avail) and not avail():
            return Health(STATE_DISABLED, "not available on this host")
        # Prefer an explicit health signal, then a running signal.
        is_healthy = getattr(svc, "is_healthy", None)
        if callable(is_healthy):
            return (Health(STATE_UP) if is_healthy()
                    else Health(STATE_DEGRADED, "self-reported unhealthy"))
        is_running = getattr(svc, "is_running", None)
        if callable(is_running):
            return (Health(STATE_UP) if is_running()
                    else Health(STATE_DOWN, "not running"))
        # No signal to probe: a wired service is assumed up.
        return Health(STATE_UP, "no health probe; assumed up while wired")

    # ------------------------------------------------------------------
    # Metrics + config (never raise)
    # ------------------------------------------------------------------

    def metrics(self) -> dict:
        try:
            if self._metrics_fn is not None:
                return dict(self._metrics_fn())
            svc = self._service
            for attr in ("status", "stats"):
                fn = getattr(svc, attr, None)
                if callable(fn):
                    out = fn()
                    return dict(out) if isinstance(out, dict) else {"value": out}
            return {}
        except Exception as exc:   # noqa: BLE001
            return {"_error": f"{type(exc).__name__}: {exc}"}

    def config(self) -> dict:
        try:
            if self._config_fn is not None:
                return dict(self._config_fn())
        except Exception as exc:   # noqa: BLE001
            return {"_error": f"{type(exc).__name__}: {exc}"}
        return {}

    # ------------------------------------------------------------------
    # Independent restart
    # ------------------------------------------------------------------

    def restart(self) -> dict:
        if not self.restartable or self._service is None:
            return {"ok": False, "error": "component is not restartable"}
        try:
            self._service.stop()
        except Exception as exc:   # noqa: BLE001
            return {"ok": False, "error": f"stop failed: {exc}"}
        try:
            self._service.start()
        except Exception as exc:   # noqa: BLE001
            return {"ok": False, "error": f"start failed: {exc}"}
        return {"ok": True}

    def snapshot(self) -> dict:
        h = self.health()
        return {"name": self.name, "kind": self.kind,
                "restartable": self.restartable,
                "health": h.to_dict(), "metrics": self.metrics(),
                "config": self.config()}


class ComponentRegistry:
    """Plugin host: registers components, aggregates health, isolates faults."""

    def __init__(self, bus=None) -> None:
        self._components: dict[str, Component] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()
        self._bus = bus
        self._last_state: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, component: Component) -> Component:
        with self._lock:
            if component.name not in self._components:
                self._order.append(component.name)
            self._components[component.name] = component
        return component

    def register_service(self, name: str, service: object, **kw) -> Component:
        """Convenience: wrap and register an existing service in one call.

        Silently skips a None service only if ``skip_if_missing`` is set;
        otherwise a None service registers as a permanently-``down`` component
        (so the UI shows it as a known-but-unwired capability)."""
        if service is None and kw.pop("skip_if_missing", False):
            return None   # type: ignore[return-value]
        kw.pop("skip_if_missing", None)
        return self.register(Component(name, service, **kw))

    def unregister(self, name: str) -> None:
        with self._lock:
            self._components.pop(name, None)
            self._last_state.pop(name, None)
            if name in self._order:
                self._order.remove(name)

    def get(self, name: str) -> Optional[Component]:
        with self._lock:
            return self._components.get(name)

    def names(self) -> list[str]:
        with self._lock:
            return list(self._order)

    # ------------------------------------------------------------------
    # Aggregate views (fault-isolated)
    # ------------------------------------------------------------------

    def snapshot(self) -> list[dict]:
        """Full per-component view; emits transition events as a side effect."""
        with self._lock:
            comps = [self._components[n] for n in self._order]
        out = []
        for c in comps:
            snap = c.snapshot()
            self._maybe_emit(c.name, snap["health"]["state"])
            out.append(snap)
        return out

    def health(self) -> dict:
        with self._lock:
            comps = [self._components[n] for n in self._order]
        result = {}
        for c in comps:
            h = c.health()
            result[c.name] = h.to_dict()
            self._maybe_emit(c.name, h.state)
        return result

    def overall(self) -> dict:
        """Aggregate: worst non-disabled state wins; counts per state."""
        health = self.health()
        counts: dict[str, int] = {}
        worst = STATE_UP
        for h in health.values():
            st = h["state"]
            counts[st] = counts.get(st, 0) + 1
            if st != STATE_DISABLED and _STATE_RANK[st] < _STATE_RANK[worst]:
                worst = st
        return {"state": worst if health else STATE_UP,
                "counts": counts, "total": len(health)}

    def restart(self, name: str) -> dict:
        comp = self.get(name)
        if comp is None:
            return {"ok": False, "error": f"no such component: {name}"}
        res = comp.restart()
        # Re-probe so the transition (and any event) reflects the restart.
        self._maybe_emit(name, comp.health().state, force=True)
        return {"name": name, **res}

    # ------------------------------------------------------------------
    # Self-heal integration — register every restartable component so the
    # existing watchdog probes it and recovers via restart(). No new loop.
    # ------------------------------------------------------------------

    def bind_self_heal(self, healer) -> int:
        bound = 0
        with self._lock:
            comps = [self._components[n] for n in self._order]
        for c in comps:
            if not c.restartable:
                continue
            healer.register(
                f"component:{c.name}",
                (lambda comp=c: comp.health().state in (STATE_UP, STATE_DISABLED)),
                (lambda comp=c: comp.restart()),
            )
            bound += 1
        return bound

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _maybe_emit(self, name: str, state: str, *, force: bool = False) -> None:
        prev = self._last_state.get(name)
        self._last_state[name] = state
        if self._bus is None:
            return
        if force or (prev is not None and prev != state):
            try:
                self._bus.publish({"type": "component", "component": name,
                                   "state": state, "previous": prev,
                                   "at": time.time()})
            except Exception:
                pass   # a logging/transport failure must never affect health
