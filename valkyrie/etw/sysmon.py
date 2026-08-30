"""Sysmon sensor (optional, auto-detected) - the richest native endpoint source.

Sysmon (Sysinternals) is an optional driver+service that writes deeply-contextual
events to ``Microsoft-Windows-Sysmon/Operational``: process creation with SHA-256
hashes, code-signing status, integrity level, and the full parent chain; network
connections *with process context*; image/DLL loads; CreateRemoteThread
(injection); ProcessAccess to LSASS (credential theft); registry and file events.

This sensor is **strictly optional**: ``available()`` returns False when Sysmon
isn't installed, so the SensorManager simply skips it - Valkyrie never requires
Sysmon, and degrades to its own polling + PowerShell/WMI sensors without it. When
Sysmon *is* present we adopt it as a superior source and correlate its events
into the same EDR pipeline.

**Avoiding duplication:** the polling process collector already reports every
process start, so this sensor emits Sysmon **process-creation (EID 1) only when
it looks suspicious** (enriched with hashes/signature/integrity), and focuses on
the high-value events the pollers *cannot* see: network-with-process, image
loads, remote-thread injection, LSASS access, and real-time registry/file
persistence.

All classifiers are pure and unit-tested against sample Sysmon XML (no Sysmon
required to test).
"""

from __future__ import annotations

import time
from typing import Optional

from .framework import Sensor
from .wineventlog import ChannelReader, parse_event_xml
from ..browser_extension_integrity import classify_extension_change
from ..behavior_score import classify_anomaly
from ..behavioral_rules import classify_behavior
from ..process_telemetry import classify_cmdline, classify_discovery, classify_process
from ..trust import is_benign_os_autorun, is_trusted_os_path
from ..telemetry import (
    ACT_FLAGGED, ACT_OBSERVED, CAT_NETWORK, CAT_PERSISTENCE, CAT_PROCESS,
    PERSIST_RUN_KEY, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, severity_rank,
    TelemetryEvent,
)

_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
# The subset we consume (Sysmon logs far more; these carry the most signal).
_EVENT_IDS = (1, 3, 6, 7, 8, 10, 11, 12, 13, 14, 25)

# Directories a legitimate kernel driver never loads from. A signed-but-
# vulnerable driver dropped here is the BYOVD pattern; genuine drivers live in
# System32\drivers / DriverStore and load from there.
_DRIVER_DROP_DIRS = ("\\appdata\\", "\\temp\\", "\\downloads\\",
                     "\\users\\public\\", "\\programdata\\", "\\$recycle")

# Known LSASS-read access masks that indicate credential dumping (Mimikatz-
# style) - a fast path of the common values, NOT the only signal (see below).
_LSASS_READ_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1010h"}

# The one access right EVERY lsass memory read needs, whatever the tool: reading
# another process's memory requires PROCESS_VM_READ (0x10). Keying on this BIT
# generalises past the fixed list above - a novel dumper with an unseen mask
# (0x1018, 0x0410, custom syscall combos) is still caught as long as it opened
# lsass to READ it - while a benign query-only open (e.g. 0x1000
# QUERY_LIMITED_INFORMATION, no VM_READ) does NOT fire, which is the FP boundary.
_PROCESS_VM_READ = 0x10


def _mask_reads_memory(granted: str) -> bool:
    """True if a GrantedAccess mask includes PROCESS_VM_READ - i.e. it can read
    the target's memory. Robust to the '0x' prefix and Sysmon's trailing 'h'."""
    try:
        return bool(int(granted.strip().rstrip("h"), 16) & _PROCESS_VM_READ)
    except (ValueError, TypeError, AttributeError):
        return False


def parse_hashes(s: str) -> dict:
    """'SHA256=ABC,MD5=DEF,IMPHASH=123' -> {'sha256':'abc', ...} (lower-cased)."""
    out: dict = {}
    for part in (s or "").split(","):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip().lower()] = v.strip().lower()
    return out


def _context(d: dict) -> dict:
    """Rich endpoint context common to Sysmon process events (T-numbers aside,
    this is the 'Endpoint Context' payload: hashes, signature, integrity, ...)."""
    hashes = parse_hashes(d.get("Hashes", "") or d.get("Hash", ""))
    return {
        "command_line": d.get("CommandLine", ""),
        "current_directory": d.get("CurrentDirectory", ""),
        "user": d.get("User", ""),
        "integrity_level": d.get("IntegrityLevel", ""),
        "logon_id": d.get("LogonId", ""),
        "session_id": d.get("TerminalSessionId", ""),
        "sha256": hashes.get("sha256", ""),
        "imphash": hashes.get("imphash", ""),
        "company": d.get("Company", ""),
        "product": d.get("Product", ""),
        "original_filename": d.get("OriginalFileName", ""),
        "file_version": d.get("FileVersion", ""),
        "parent_pid": int(d.get("ParentProcessId", 0) or 0),
        "parent_image": d.get("ParentImage", ""),
        "parent_command_line": d.get("ParentCommandLine", ""),
        "signature": d.get("Signature", ""),
        "signature_status": d.get("SignatureStatus", ""),
        "signed": d.get("Signed", ""),
    }


def _name(path: str) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1]


# --- per-EID classification (pure) ---
def classify_sysmon(event_id: int, d: dict) -> Optional[dict]:
    """Return a dict of TelemetryEvent kwargs to emit, or None to skip.

    Pure: takes the parsed EventData dict, returns emit args. Kept explicit per
    event id so each mapping (and MITRE technique) is unit-testable."""
    eid = int(event_id)

    # EID 1 - process creation. Emit ONLY when suspicious (the poller covers the
    # rest), but enrich heavily so correlation has full context.
    #
    # This runs the SAME four-classifier stack as the polling collector
    # (process_telemetry.ProcessRecord.to_event). It previously ran only
    # classify_process(), which judges image name / path / parent and never
    # sees the command line - so `powershell.exe -enc <base64>` launched from
    # explorer.exe scored as ordinary PowerShell, fell under the SEV_LOW gate
    # below, and was discarded before the 32 MITRE-mapped IOA rules ever ran.
    #
    # That was the more damaging half of the bug: Sysmon is the *higher*
    # fidelity source (it sees short-lived processes the ~2s poller misses
    # entirely, and it carries the full command line), yet it was running a
    # strictly weaker pipeline than the poller. Execution, Defense Evasion and
    # Discovery are almost entirely command-line-shaped techniques, which is
    # why those three tactics measured 0% while persistence and C2 - which key
    # off registry and network artefacts - did not.
    #
    # The severity gate is unchanged and still applies; it is simply evaluated
    # AFTER every classifier has had the command line, so an escalation can
    # actually happen before the event is dropped.
    if eid == 1:
        image = d.get("Image", "")
        parent = _name(d.get("ParentImage", ""))
        name = _name(image)
        cmdline = d.get("CommandLine", "") or ""

        sev, labels, reason = classify_process(name, image, parent)
        labels = list(labels)
        technique = ""
        all_techniques: list[str] = []

        # Command-line heuristics (encoded/hidden PowerShell, download cradles).
        csev, clabels, creason = classify_cmdline(name, cmdline)
        if severity_rank(csev) > severity_rank(sev):
            sev = csev
        for lab in clabels:
            if lab not in labels:
                labels.append(lab)
        reason = "; ".join(r for r in (reason, creason) if r)

        # The MITRE-mapped IOA rule content layer (32 rules). Its top hit
        # carries the exact ATT&CK technique so the kill-chain gets a real
        # tactic instead of one inferred from labels.
        behavior = classify_behavior(name, parent, cmdline, image)
        if behavior is not None:
            if severity_rank(behavior["severity"]) > severity_rank(sev):
                sev = behavior["severity"]
            for lab in behavior["labels"]:
                if lab not in labels:
                    labels.append(lab)
            reason = "; ".join(r for r in (reason, behavior["reason"]) if r)
            technique = behavior["technique"]
            all_techniques = list(behavior.get("all_techniques") or [])

        # The generalizing anomaly scorer - catches shapes no rule was written
        # for (masquerade, obfuscation, impossible ancestry). Defers to a
        # rule's exact technique when one already fired.
        anomaly = classify_anomaly(name, parent, cmdline, image)
        if anomaly is not None:
            if severity_rank(anomaly["severity"]) > severity_rank(sev):
                sev = anomaly["severity"]
            for lab in anomaly["labels"]:
                if lab not in labels:
                    labels.append(lab)
            reason = "; ".join(r for r in (reason, anomaly["reason"]) if r)
            if not technique:
                technique = anomaly["technique"]
            # Preserve the anomaly's technique even when a rule already claimed
            # the primary slot: an encoded PowerShell is BOTH T1059.001
            # (EncodedCommand, from the rule) AND T1027 (obfuscation, from the
            # anomaly nose) - dropping either loses real ATT&CK context.
            if anomaly.get("technique") and anomaly["technique"] not in all_techniques:
                all_techniques.append(anomaly["technique"])

        # Discovery-tactic weak labeling. Must run on THIS path, not just the
        # poller: a lone discovery command is INFO by design (never alerts on
        # its own), but the reconnaissance-burst sequence needs to SEE several
        # of them to fire - and these commands (whoami, tasklist, net view)
        # exit in milliseconds, so the 2s poller is exactly the source that
        # loses them. Sysmon/4688 is the only source that reliably catches
        # them, which makes this the delivery path the burst depends on.
        _, dlabels, dreason, dtechnique = classify_discovery(name, cmdline)
        for lab in dlabels:
            if lab not in labels:
                labels.append(lab)
        reason = "; ".join(r for r in (reason, dreason) if r)
        if not technique:
            technique = dtechnique
        if dtechnique and dtechnique not in all_techniques:
            all_techniques.append(dtechnique)

        # A discovery-labeled event is deliberately INFO and would otherwise be
        # dropped by the gate below. Let it through: the engine's ingest
        # chokepoint routes 'discovery_command' to the sequence engine BEFORE
        # its own severity gate, and drops it afterwards - so this stays
        # non-alerting on its own while still feeding the burst combiner.
        if "discovery_command" in labels:
            return {
                "category": CAT_PROCESS, "activity": "exec",
                "actor_pid": int(d.get("ProcessId", 0) or 0), "actor_name": name,
                "actor_path": image, "target": {"path": image},
                "severity": sev, "labels": labels,
                "reason": reason or "process creation",
                "technique": technique, "all_techniques": all_techniques,
                "context": _context(d),
            }

        if severity_rank(sev) < severity_rank(SEV_LOW):
            return None
        return {
            "category": CAT_PROCESS, "activity": "exec",
            "actor_pid": int(d.get("ProcessId", 0) or 0), "actor_name": name,
            "actor_path": image, "target": {"path": image},
            "severity": sev, "labels": labels, "reason": reason or "process creation",
            "technique": technique, "all_techniques": all_techniques,
            "context": _context(d),
        }

    # EID 3 - network connection (process context DNS/firewall lacks).
    if eid == 3:
        if str(d.get("Initiated", "true")).lower() != "true":
            return None
        dip = d.get("DestinationIp", "")
        if _is_private(dip):
            return None                       # LAN chatter - low value, high volume
        image = d.get("Image", "")
        return {
            "category": CAT_NETWORK, "activity": "connect",
            "actor_pid": int(d.get("ProcessId", 0) or 0), "actor_name": _name(image),
            "actor_path": image,
            "target": {"ip": dip, "port": int(d.get("DestinationPort", 0) or 0),
                       "domain": d.get("DestinationHostname", ""),
                       "proto": d.get("Protocol", "")},
            "severity": SEV_INFO, "labels": ["outbound"], "reason": "outbound connection",
            "technique": "", "context": {"user": d.get("User", "")},
        }

    # EID 6 - kernel driver load. BYOVD (bring-your-own-vulnerable-driver) is
    # the dominant EDR-killer technique of 2024-25 (Backstab, AuKill, Terminator
    # and friends): load a signed-but-vulnerable - or plainly unsigned - kernel
    # driver, then use its raw kernel access to terminate protection. Two
    # list-free tells, either of which is abnormal on a healthy host:
    #   * unsigned / invalid signature - modern Windows blocks unsigned drivers
    #     via DSE, so a load getting through means signing was subverted;
    #   * loaded from a user-writable directory - real drivers ship signed in
    #     System32\drivers / DriverStore and never load out of %TEMP%/Downloads.
    # A signed driver loading from the OS driver store (the normal case) is
    # ignored, so this does not fire on ordinary GPU/AV/VPN driver loads.
    if eid == 6:
        loaded = d.get("ImageLoaded", "")
        low = loaded.lower().replace("/", "\\")
        status = (d.get("SignatureStatus", "") or "").lower()
        signed = (d.get("Signed", "") or "").lower()
        bad_sig = signed == "false" or (status not in ("", "valid"))
        dropped = any(p in low for p in _DRIVER_DROP_DIRS)
        if not (bad_sig or dropped):
            return None
        why = []
        if bad_sig:
            why.append("unsigned/invalid signature")
        if dropped:
            why.append("loaded from a user-writable directory")
        labels = ["driver_load"]
        labels.append("byovd" if dropped else "unsigned_driver")
        return {
            "category": CAT_PROCESS, "activity": "driver_load",
            "actor_pid": int(d.get("ProcessId", 0) or 0),
            "actor_name": _name(loaded), "actor_path": loaded,
            "target": {"path": loaded},
            "severity": SEV_HIGH, "labels": labels,
            "reason": "kernel driver load (" + ", ".join(why) + ")",
            "technique": "T1068 — Exploitation for Privilege Escalation (vulnerable driver)",
            "context": {"sha256": parse_hashes(d.get("Hashes", "")).get("sha256", ""),
                        "signature": d.get("Signature", ""),
                        "signature_status": d.get("SignatureStatus", ""),
                        "signed": d.get("Signed", "")},
        }

    # EID 7 - image/DLL load. Emit only unsigned / invalid-signature loads.
    if eid == 7:
        status = (d.get("SignatureStatus", "") or "").lower()
        signed = (d.get("Signed", "") or "").lower()
        if status in ("valid",) or signed == "true":
            return None
        loaded = d.get("ImageLoaded", "")
        return {
            "category": CAT_PROCESS, "activity": "image_load",
            "actor_pid": int(d.get("ProcessId", 0) or 0), "actor_name": _name(d.get("Image", "")),
            "actor_path": d.get("Image", ""),
            "target": {"path": loaded},
            "severity": SEV_MEDIUM, "labels": ["unsigned_module"],
            "reason": f"unsigned/invalid module load ({_name(loaded)})",
            "technique": "T1574 — Hijack Execution Flow",
            "context": {"sha256": parse_hashes(d.get("Hashes", "")).get("sha256", ""),
                        "signature_status": d.get("SignatureStatus", "")},
        }

    # EID 8 - CreateRemoteThread -> classic code injection.
    if eid == 8:
        return {
            "category": CAT_PROCESS, "activity": "remote_thread",
            "actor_pid": int(d.get("SourceProcessId", 0) or 0),
            "actor_name": _name(d.get("SourceImage", "")),
            "actor_path": d.get("SourceImage", ""),
            "target": {"path": d.get("TargetImage", ""),
                       "pid": int(d.get("TargetProcessId", 0) or 0)},
            "severity": SEV_HIGH, "labels": ["remote_thread_injection"],
            "reason": f"CreateRemoteThread into {_name(d.get('TargetImage',''))}",
            "technique": "T1055 — Process Injection",
            "context": {"start_module": d.get("StartModule", ""),
                        "start_function": d.get("StartFunction", "")},
        }

    # EID 10 - ProcessAccess. Flag reads of LSASS (credential dumping).
    if eid == 10:
        target = _name(d.get("TargetImage", "")).lower()
        if target != "lsass.exe":
            return None
        granted = (d.get("GrantedAccess", "") or "").lower()
        # Generalised: HIGH when the mask is a known dump mask OR simply includes
        # PROCESS_VM_READ (reads lsass memory) - so an unseen variant is caught,
        # not just the six enumerated masks. Query-only opens stay MEDIUM.
        sev = (SEV_HIGH if (granted in _LSASS_READ_MASKS
                            or _mask_reads_memory(granted))
               else SEV_MEDIUM)
        return {
            "category": CAT_PROCESS, "activity": "process_access",
            "actor_pid": int(d.get("SourceProcessId", 0) or 0),
            "actor_name": _name(d.get("SourceImage", "")),
            "actor_path": d.get("SourceImage", ""),
            "target": {"path": d.get("TargetImage", ""),
                       "pid": int(d.get("TargetProcessId", 0) or 0),
                       "access": d.get("GrantedAccess", "")},
            "severity": sev, "labels": ["lsass_access", "credential_access"],
            "reason": f"LSASS memory access (GrantedAccess={d.get('GrantedAccess','')})",
            "technique": "T1003.001 — LSASS Memory",
            "context": {"call_trace": (d.get("CallTrace", "") or "")[:400]},
        }

    # EID 11 - browser-extension state or startup-folder persistence.
    if eid == 11:
        extension = classify_extension_change(eid, d)
        if extension is not None:
            return extension
        fn = (d.get("TargetFilename", "") or "")
        low = fn.lower().replace("/", "\\")
        if "\\startup\\" not in low and "\\start menu\\programs\\startup" not in low:
            return None
        writer = d.get("Image", "")
        # Windows Update / signed OS components legitimately place items in the
        # startup path. If a trusted OS binary is the writer, observe rather than
        # alert (see valkyrie/trust.py). A user/attacker binary still flags.
        trusted = is_benign_os_autorun(writer, fn)
        return {
            "category": CAT_PERSISTENCE, "activity": PERSIST_RUN_KEY,
            "actor_pid": int(d.get("ProcessId", 0) or 0), "actor_name": _name(writer),
            "actor_path": writer,
            "target": {"location": fn, "command": writer},
            "severity": SEV_INFO if trusted else SEV_MEDIUM,
            "labels": (["persistence_startup_folder", "trusted_os"] if trusted
                       else ["persistence_startup_folder"]),
            "reason": ("OS component wrote to Startup (trusted)" if trusted
                       else "file dropped in Startup folder"),
            "technique": "T1547.001 — Registry Run Keys / Startup Folder",
            "context": {},
        }

    # EID 12/13/14 - registry create/set/rename in an autorun or extension
    # policy key. Rename matters because staging a value elsewhere and moving
    # it into policy must not bypass the same invariant.
    if eid in (12, 13, 14):
        extension = classify_extension_change(eid, d)
        if extension is not None:
            return extension
        obj = (d.get("TargetObject", "") or "")
        low = obj.lower()
        if not any(k in low for k in ("\\run\\", "\\runonce\\", "currentversion\\run",
                                      "\\services\\", "userinit", "\\winlogon\\")):
            return None
        writer = d.get("Image", "")
        target = d.get("Details", "")
        # OS self-maintenance (services.exe, sihost, TrustedInstaller, Defender,
        # Edge, dismhost, WMIADAP) writes autorun keys constantly - the single
        # largest source of persistence false positives on a live box. Trust the
        # write when a trusted OS binary makes it and the target is not in a
        # world-writable scratch dir; a trusted process dropping an autorun into
        # %TEMP% is the abuse case and still flags.
        trusted = is_benign_os_autorun(writer, target)
        return {
            "category": CAT_PERSISTENCE, "activity": PERSIST_RUN_KEY,
            "actor_pid": int(d.get("ProcessId", 0) or 0), "actor_name": _name(writer),
            "actor_path": writer,
            "target": {"location": obj, "command": target},
            "severity": SEV_INFO if trusted else SEV_MEDIUM,
            "labels": (["persistence_run_key", "trusted_os"] if trusted
                       else ["persistence_run_key"]),
            "reason": ("OS component autorun write (trusted)" if trusted
                       else "autorun registry modification"),
            "technique": "T1547.001 — Registry Run Keys / Startup Folder",
            "context": {},
        }

    # EID 25 - process tampering (process hollowing / herpaderping).
    if eid == 25:
        return {
            "category": CAT_PROCESS, "activity": "process_tamper",
            "actor_pid": int(d.get("ProcessId", 0) or 0), "actor_name": _name(d.get("Image", "")),
            "actor_path": d.get("Image", ""), "target": {"path": d.get("Image", "")},
            "severity": SEV_HIGH, "labels": ["process_tampering"],
            "reason": f"process tampering ({d.get('Type','')})",
            "technique": "T1055.012 — Process Hollowing",
            "context": {},
        }

    return None


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    if ip.startswith(("10.", "192.168.", "127.", "169.254.", "::1", "fe80", "fc", "fd")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


class SysmonSensor(Sensor):
    name = "sysmon"
    interval = 1.5

    def __init__(self) -> None:
        super().__init__()
        self._reader = ChannelReader(_CHANNEL, _EVENT_IDS)

    def available(self) -> bool:
        # False when Sysmon isn't installed -> SensorManager skips us cleanly.
        return self._reader.available()

    def _collect_once(self) -> None:
        for xml in self._reader.read_new():
            ev = parse_event_xml(xml)
            if not ev:
                continue
            args = classify_sysmon(ev.get("event_id", 0), ev.get("data", {}))
            if args:
                self._emit(ev, args)

    def _emit(self, ev: dict, args: dict) -> None:
        sev = args["severity"]
        action = ACT_FLAGGED if severity_rank(sev) >= severity_rank(SEV_MEDIUM) else ACT_OBSERVED
        context = args.pop("context", {})
        technique = args.pop("technique", "")
        all_techniques = args.pop("all_techniques", [])
        tgt = args.get("target", {})
        dedup = f"sysmon:{ev.get('event_id')}:{args['actor_pid']}:" \
                f"{tgt.get('path') or tgt.get('ip') or tgt.get('location') or ''}"
        self.submit(TelemetryEvent(
            category=args["category"], activity=args["activity"], action=action,
            ts=time.time(),
            actor_pid=args["actor_pid"], actor_name=args["actor_name"],
            actor_path=args.get("actor_path", ""),
            target=tgt, severity=sev, reason=args["reason"], source="etw.sysmon",
            labels=args.get("labels", []),
            fields={"technique": technique, "all_techniques": all_techniques,
                    "event_id": ev.get("event_id", 0),
                    "user_sid": ev.get("user_sid", ""), "_dedup": dedup[:200], **context},
        ))
