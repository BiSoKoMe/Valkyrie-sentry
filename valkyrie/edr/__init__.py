"""Valkyrie EDR layer — detection, incidents, hunting, response, investigation.

Valkyrie already has excellent *sensors* (the DNS sinkhole, firewall answer-IP
screening, the behavioural + self-learning intelligence engines). This package
is the *SOC layer* on top of them: it turns that live signal into things a
defender actually works with — correlated **incidents** with **timelines**,
a **threat-hunting** query surface, audited **response** actions (local and,
via the fleet, remote), and an **AI-assisted investigation** writeup — all
extensible through a **plugin architecture**.

The single entry point is :class:`EdrEngine`. Everything else is a component it
wires together, but each is independently importable and testable.
"""

from __future__ import annotations

from .engine import EdrEngine
from .hunt import ThreatHunter
from .investigate import Investigator
from .plugins import (
    DetectionPlugin,
    EnrichmentPlugin,
    PluginBase,
    PluginContext,
    PluginRegistry,
    ResponderPlugin,
)
from .response import ResponseManager
from .schema import Detection, Incident, ResponseAction, TimelineEntry
from .store import EdrStore

__all__ = [
    "Detection",
    "DetectionPlugin",
    "EdrEngine",
    "EdrStore",
    "EnrichmentPlugin",
    "Incident",
    "Investigator",
    "PluginBase",
    "PluginContext",
    "PluginRegistry",
    "ResponderPlugin",
    "ResponseAction",
    "ResponseManager",
    "ThreatHunter",
    "TimelineEntry",
]
