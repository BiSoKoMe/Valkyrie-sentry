"""PowerShell script-block sensor (ETW-backed, real-time).

Consumes Microsoft-Windows-PowerShell/Operational **4104** (script-block logging)
and **4103** (module/pipeline). 4104 records the *deobfuscated* script text the
engine is about to run — the single highest-value real-time signal on Windows
that polling cannot obtain. Each script block is classified with explainable
heuristics and emitted as a normalized ``TelemetryEvent`` into the same
EventBus → EDR pipeline as every other collector.

Honesty: script-block logging must be enabled (it is by default on modern
Windows; the channel is checked at start). This sensor sees what PowerShell
logs; a caller that disables logging is out of scope (a hardening detection in
its own right — a separate concern from this collector).
"""

from __future__ import annotations

import re
import time
from typing import Optional

from .framework import Sensor
from .wineventlog import ChannelReader, parse_event_xml
from ..telemetry import (
    ACT_FLAGGED, ACT_OBSERVED, CAT_MALWARE, CAT_PROCESS,
    SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM,
    severity_rank, TelemetryEvent,
)

_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_EVENT_IDS = (4104,)          # script-block; 4103 is pipeline, noisier — omit for now

# Script blocks shorter than this are prompt fragments and tab-completion noise;
# submitting them to AMSI costs a round trip per keystroke for no signal.
_AMSI_MIN_SCRIPT_LEN = 24

# ── pure classifier (unit-tested; no OS calls) ─────────────────────────────
# Each rule: (compiled regex, label, severity, MITRE technique, human reason).
_RULES: list[tuple[re.Pattern, str, str, str, str]] = [
    (re.compile(r"-e(nc(odedcommand)?)?\b\s+[A-Za-z0-9+/=]{40,}", re.I),
     "encoded_command", SEV_HIGH, "T1027", "base64 -EncodedCommand payload"),
    (re.compile(r"frombase64string", re.I),
     "base64_decode", SEV_MEDIUM, "T1140", "inline base64 decoding"),
    (re.compile(r"(downloadstring|downloadfile|downloaddata|net\.webclient|"
                r"invoke-webrequest|\biwr\b|\bwget\b|\bcurl\b|start-bitstransfer)", re.I),
     "download", SEV_MEDIUM, "T1105", "remote content download"),
    (re.compile(r"(invoke-expression|\biex\b|\.invoke\(\)|&\s*\(\s*\$)", re.I),
     "dynamic_exec", SEV_MEDIUM, "T1059.001", "dynamic code execution (IEX)"),
    (re.compile(r"amsi(utils|initfailed|context|scanbuffer)|"
                r"System\.Management\.Automation\.Amsi", re.I),
     "amsi_bypass", SEV_HIGH, "T1562.001", "AMSI tampering / bypass"),
    (re.compile(r"(set|add)-mppreference|-disablerealtimemonitoring|"
                r"-exclusionpath|-exclusionprocess", re.I),
     "defender_tamper", SEV_HIGH, "T1562.001", "Defender tampering"),
    (re.compile(r"(mimikatz|sekurlsa|lsadump|invoke-mimikatz|dumpcreds|"
                r"comsvcs.*minidump|rundll32.*minidump)", re.I),
     "credential_access", SEV_HIGH, "T1003", "credential-dumping tooling"),
    (re.compile(r"(new-scheduledtask|register-scheduledtask|schtasks\s+/create)", re.I),
     "persistence_task", SEV_MEDIUM, "T1053.005", "scheduled-task persistence"),
    (re.compile(r"(-w(indowstyle)?\s+hidden|-nop\b|-noprofile|-noni|-noninteractive)", re.I),
     "stealth_flags", SEV_LOW, "T1059.001", "stealthy execution flags"),
    (re.compile(r"(reflection\.assembly|\[reflection\.assembly\]|virtualalloc|"
                r"createthread|memcpy|writeprocessmemory)", re.I),
     "injection_primitive", SEV_HIGH, "T1055", "in-memory/injection primitives"),
]


def classify_powershell(script: str) -> tuple[str, list[str], str, str]:
    """Return (severity, labels, technique, reason) for a script block.
    Pure and deterministic — the entire heuristic surface for unit testing."""
    text = script or ""
    severity = SEV_INFO
    labels: list[str] = []
    reasons: list[str] = []
    technique = ""
    for rx, label, sev, tech, reason in _RULES:
        if rx.search(text):
            labels.append(label)
            reasons.append(reason)
            if severity_rank(sev) > severity_rank(severity):
                severity, technique = sev, tech
    # Long, single-line, high-entropy one-liners are a soft signal on their own.
    if severity == SEV_INFO and len(text) > 1200 and text.count("\n") <= 1:
        labels.append("obfuscation")
        reasons.append("very long single-line script")
        severity = SEV_LOW
    return severity, labels, technique, "; ".join(reasons)


# ── the sensor ─────────────────────────────────────────────────────────────
class PowerShellSensor(Sensor):
    name = "powershell"
    interval = 1.5

    def __init__(self, scanner=None) -> None:
        """``scanner`` is an optional ``valkyrie.amsi.AmsiScanner``.

        When supplied, each script block is also submitted to the OS antimalware
        provider, so a heuristic "this looks obfuscated" can be upgraded to an
        engine-backed conviction. Absent (or unavailable), the sensor behaves
        exactly as before — the corroborator is additive, never load-bearing.
        """
        super().__init__()
        self._reader = ChannelReader(_CHANNEL, _EVENT_IDS)
        self._scanner = scanner
        self.amsi_scans = 0
        self.amsi_convictions = 0

    def available(self) -> bool:
        return self._reader.available()

    def _collect_once(self) -> None:
        for xml in self._reader.read_new():
            ev = parse_event_xml(xml)
            if not ev:
                continue
            self._emit_event(ev)

    def _emit_event(self, ev: dict) -> None:
        data = ev.get("data", {})
        script = data.get("ScriptBlockText", "") or ""
        sbid = data.get("ScriptBlockId", "")
        part = data.get("MessageNumber", "1")
        total = data.get("MessageTotal", "1")
        path = data.get("Path", "") or ""
        pid = int(ev.get("process_id", 0) or 0)

        severity, labels, technique, reason = classify_powershell(script)
        category = CAT_PROCESS
        amsi_fields: dict = {}

        # Corroborate with the OS antimalware provider. A conviction is an
        # external engine's verdict on the *deobfuscated* text PowerShell was
        # about to run — stronger evidence than any shape heuristic, so it
        # overrides severity and re-categorizes the event as malware.
        verdict = self._amsi_verdict(script, path)
        if verdict is not None:
            amsi_fields = {"amsi_disposition": verdict.disposition,
                           "amsi_result": verdict.result}
            if verdict.is_malware:
                self.amsi_convictions += 1
                category = CAT_MALWARE
                severity = SEV_CRITICAL
                labels = list(labels) + ["amsi_detected"]
                technique = technique or "T1059.001"
                reason = ("antimalware provider convicted this script block"
                          + (f"; {reason}" if reason else ""))

        action = ACT_FLAGGED if severity_rank(severity) >= severity_rank(SEV_MEDIUM) else ACT_OBSERVED

        snippet = script.strip().replace("\r", " ").replace("\n", " ")
        if len(snippet) > 300:
            snippet = snippet[:300] + "…"

        self.submit(TelemetryEvent(
            category=category,
            activity="script_block",
            action=action,
            ts=time.time(),
            actor_pid=pid,
            actor_name="powershell.exe",
            actor_path=path,
            target={"command": snippet},
            severity=severity,
            reason=reason or "PowerShell script block",
            source="etw.powershell",
            labels=labels,
            fields={
                "technique": technique,
                "scriptblock_id": sbid,
                "message": f"{part}/{total}",
                "script_len": len(script),
                "user_sid": ev.get("user_sid", ""),
                "script": script if len(script) <= 8000 else script[:8000],
                **amsi_fields,
                # Dedup on the exact script-block fragment.
                "_dedup": f"{sbid}:{part}",
            },
        ))

    def _amsi_verdict(self, script: str, path: str):
        """Submit a script block to AMSI. Returns a verdict, or None if not scanned.

        Never raises and never blocks the sensor: a scanner that errors is a
        missing corroborator, not a missing detection.
        """
        if self._scanner is None or len(script) < _AMSI_MIN_SCRIPT_LEN:
            return None
        try:
            if not self._scanner.is_running():
                return None
            verdict = self._scanner.scan_string(
                script, content_name=path or "powershell-scriptblock")
        except Exception:
            return None
        self.amsi_scans += 1
        return verdict if verdict.scanned else None

    def health(self) -> dict:
        h = super().health()
        h.update({"amsi_enabled": self._scanner is not None,
                  "amsi_scans": self.amsi_scans,
                  "amsi_convictions": self.amsi_convictions})
        return h
