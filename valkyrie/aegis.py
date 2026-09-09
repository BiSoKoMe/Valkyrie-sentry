"""Aegis investigation facade. All cases and authority remain owned by EdrEngine."""
from __future__ import annotations

from typing import Callable, Optional


class AegisInvestigator:
    def __init__(self, engine, sensor_health_fn: Optional[Callable[[], Optional[dict]]] = None):
        self._engine = engine
        self._sensor_health_fn = sensor_health_fn

    def _sensor_health(self) -> dict:
        # A case list with zero open incidents must never read as "all clear"
        # merely because the sensors feeding it went silent - that is the
        # exact silent-success shape this facade exists to rule out. An
        # unavailable or throwing health source is reported as its own
        # explicit state, never folded into "not present" (which would look
        # identical to "nothing to report" on the wire).
        if self._sensor_health_fn is None:
            return {"overall": "UNKNOWN", "reason": "no sensor health source wired"}
        try:
            result = self._sensor_health_fn()
        except Exception as exc:                          # noqa: BLE001
            return {"overall": "UNKNOWN", "reason": f"sensor health check failed: {type(exc).__name__}"}
        if result is None:
            return {"overall": "UNKNOWN", "reason": "sensor health not initialized"}
        return result

    def status(self) -> dict:
        return {"schema_version": 1, "component": "aegis", "scope": "local-investigation",
                "case_backend": "edr", "independent_enforcement": False,
                "delivery": self._engine.delivery_status(),
                "sensor_health": self._sensor_health()}

    def cases(self, *, limit: int = 100, status=None) -> list[dict]:
        return self._engine.list_incidents(limit=max(1, min(int(limit), 200)), status=status)

    def case(self, case_id: str):
        return self._engine.get_incident(case_id)


class NyxExposure:
    """Compatibility facade for the old Aegis privacy reasoning API."""
    def __init__(self, engine):
        self._engine = engine

    def status(self) -> dict:
        return self._engine.aegis_status()

    def ledger(self, limit: int = 100) -> list[dict]:
        return self._engine.aegis_ledger(max(1, min(int(limit), 512)))
