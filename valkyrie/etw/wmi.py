"""WMI-Activity sensor (ETW-backed, real-time).

Consumes Microsoft-Windows-WMI-Activity/Operational, focusing on the highest-
signal events: **permanent WMI event-subscription persistence** — the
``__FilterToConsumerBinding`` that ties an ``__EventFilter`` (trigger) to a
``CommandLineEventConsumer`` / ``ActiveScriptEventConsumer`` (payload). This is a
classic fileless persistence + privilege-survival technique (MITRE **T1546.003**),
and remote WMI method calls map to **T1047**.

Event IDs of interest (Operational channel):
  * **5861** — permanent consumer→filter binding registered (persistence).
  * **5860** — temporary event consumer registered.
  * **5859** — ESS (event subscription service) started.

The binding details live in the event's ``<UserData>`` (Consumer, Query,
PossibleCause, Namespace). ``classify_wmi`` is pure and tolerant of the schema
differences between Windows versions — it scores over the concatenated text.
"""

from __future__ import annotations

import re
import time
from typing import Optional

from .framework import Sensor
from .wineventlog import ChannelReader, parse_event_xml
from .powershell import classify_powershell
from ..telemetry import (
    ACT_FLAGGED, ACT_OBSERVED, CAT_PERSISTENCE, PERSIST_WMI,
    SEV_HIGH, SEV_INFO, SEV_MEDIUM, severity_rank, TelemetryEvent,
)

_CHANNEL = "Microsoft-Windows-WMI-Activity/Operational"
_EVENT_IDS = (5861, 5860, 5859)

# Extractors over the (schema-tolerant) combined UserData text.
_RE_CONSUMER = re.compile(r"(CommandLineEventConsumer|ActiveScriptEventConsumer|"
                          r"LogFileEventConsumer|SMTPEventConsumer|"
                          r"ScriptingEngine)[^;\n]*", re.I)
_RE_CMD = re.compile(r'(?:CommandLineTemplate|ExecutablePath|ScriptText|ScriptFileName)'
                     r'\s*=\s*["\']?([^"\';\n]+)', re.I)
_RE_QUERY = re.compile(r'(?:Query|QueryString)\s*=\s*["\']?([^"\'\n]+)', re.I)
_RE_NAMESPACE = re.compile(r'Namespace\s*=\s*["\']?([^"\';\n]+)', re.I)


def classify_wmi(text: str, consumer_cmd: str = "") -> tuple[str, list[str], str, str]:
    """Return (severity, labels, technique, reason) for a WMI subscription event.
    Pure; scores over the binding text (+ any extracted consumer command)."""
    t = text or ""
    labels: list[str] = []
    reasons: list[str] = []
    severity = SEV_INFO
    technique = ""

    def raise_to(sev, tech):
        nonlocal severity, technique
        if severity_rank(sev) > severity_rank(severity):
            severity, technique = sev, tech

    if re.search(r"ActiveScriptEventConsumer", t, re.I):
        labels.append("wmi_script_consumer")
        reasons.append("ActiveScriptEventConsumer (in-memory script persistence)")
        raise_to(SEV_HIGH, "T1546.003")
    if re.search(r"CommandLineEventConsumer", t, re.I):
        labels.append("wmi_command_consumer")
        reasons.append("CommandLineEventConsumer (command persistence)")
        raise_to(SEV_HIGH, "T1546.003")
    # Any permanent binding at all is persistence worth surfacing.
    if re.search(r"__FilterToConsumerBinding|ESStoConsumerBinding|ConsumerBinding", t, re.I):
        labels.append("persistence_wmi")
        reasons.append("permanent WMI event subscription")
        raise_to(SEV_MEDIUM, "T1546.003")
    # Interval/timer or logon triggers are the usual malicious filter shapes.
    if re.search(r"__InstanceModificationEvent|Win32_LocalTime|Win32_PerfFormatted|"
                 r"WITHIN\s+\d+|__TimerEvent|Win32_LogonSession", t, re.I):
        labels.append("wmi_timer_trigger")
        reasons.append("timer/logon-triggered filter")
        raise_to(SEV_MEDIUM, "T1546.003")

    # Cross-apply the PowerShell classifier to any embedded consumer command —
    # a WMI consumer that runs an encoded PowerShell payload is doubly damning.
    if consumer_cmd:
        ps_sev, ps_labels, ps_tech, ps_reason = classify_powershell(consumer_cmd)
        if ps_labels:
            labels.extend(f"wmi_{l}" if not l.startswith("wmi_") else l for l in ps_labels)
            if ps_reason:
                reasons.append(ps_reason)
            raise_to(ps_sev, ps_tech or technique)

    return severity, labels, technique, "; ".join(reasons)


class WmiActivitySensor(Sensor):
    name = "wmi"
    interval = 2.0

    def __init__(self) -> None:
        super().__init__()
        self._reader = ChannelReader(_CHANNEL, _EVENT_IDS)

    def available(self) -> bool:
        return self._reader.available()

    def _collect_once(self) -> None:
        for xml in self._reader.read_new():
            ev = parse_event_xml(xml)
            if ev:
                self._emit_event(ev)

    def _emit_event(self, ev: dict) -> None:
        data = ev.get("data", {})
        # Concatenate everything WMI put in the event for schema-tolerant scoring.
        blob = " ".join(str(v) for v in data.values() if isinstance(v, str))
        consumer_m = _RE_CONSUMER.search(blob)
        cmd_m = _RE_CMD.search(blob)
        query_m = _RE_QUERY.search(blob)
        ns_m = _RE_NAMESPACE.search(blob)
        consumer = consumer_m.group(0).strip() if consumer_m else ""
        command = cmd_m.group(1).strip() if cmd_m else ""
        query = query_m.group(1).strip() if query_m else ""
        namespace = ns_m.group(1).strip() if ns_m else ""

        severity, labels, technique, reason = classify_wmi(blob, command)
        if severity == SEV_INFO and not labels:
            # Not a subscription/persistence event (e.g. a plain provider start).
            return
        action = ACT_FLAGGED if severity_rank(severity) >= severity_rank(SEV_MEDIUM) else ACT_OBSERVED

        location = consumer or f"WMI {ev.get('operation', 'subscription')}"
        self.submit(TelemetryEvent(
            category=CAT_PERSISTENCE,
            activity=PERSIST_WMI,
            action=action,
            ts=time.time(),
            actor_pid=int(ev.get("process_id", 0) or 0),
            actor_name="WmiPrvSE.exe",
            target={"location": location, "command": command or query},
            severity=severity,
            reason=reason or "WMI event subscription",
            source="etw.wmi",
            labels=labels,
            fields={
                "technique": technique,
                "consumer": consumer,
                "query": query,
                "namespace": namespace,
                "user_sid": ev.get("user_sid", ""),
                "event_id": ev.get("event_id", 0),
                "_dedup": f"wmi:{consumer}:{command or query}"[:200],
            },
        ))
