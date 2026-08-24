"""Control taxonomy — every Valkyrie control classified by function.

IIBA/IEEE's *Cybersecurity Analysis* handbook (§4.2.3) sorts security
controls into seven functional classes: preventive, detective, corrective,
deterrent, compensating, directive, recovery. Valkyrie had never classified
itself this way. Doing so honestly (reading what each module actually DOES,
not what its docstring aspires to) surfaced findings this module records
rather than hides:

  * **deterrent was an unnamed category.** ``decoys.py`` (and, to a lesser
    extent, ``ransomware_shield.py``'s canaries) plant bait specifically so
    an intruder announces themselves by touching it. That is textbook
    deterrence — a sophisticated attacker who suspects tripwires exist
    behaves more cautiously even before triggering one — but nothing in
    the codebase ever named it that; both were filed purely as detection.

  * **compensating was EMPTY before this pass.** When Sysmon (the sensor
    ``docs/adr/0048-sysmon-dependency.md`` names as Valkyrie's most-depended-
    on) goes dark, nothing actively substituted for the lost visibility —
    detection just silently fell back to whatever ran independently of it.
    ``sensor_tamper.py`` now activates a real compensating action (tightening
    ``process_telemetry.ProcessCollector``'s poll interval) on that specific
    transition. This is PARTIAL and the module says so below — a userland
    poll cannot see the ETW-only signals Sysmon uniquely provides.

  * **recovery is populated almost entirely by Valkyrie undoing its OWN
    actions**, not by recovering a user's data after real attacker damage.
    The reversibility work (``valkyrie/edr/reversibility.py``,
    ``restore_persistence``, ``release_isolation``, ``mac_randomizer.restore``,
    ``telemetry_killer.restore``) is genuine recovery in the NIST CSF
    "Recover" sense — it restores the host to its pre-action state. But
    there is NO backup-and-restore of a user's actual files before/after
    ransomware encrypts them; ``ransomware_shield`` detects and kills the
    encrypting process, and re-arms its own canaries, but never recovers
    the user's real documents. That gap is reported honestly, not filled
    with an invented control — building real file backup is a substantial
    feature, out of scope for a taxonomy pass.

  * **directive over-promises in one place.** ``decision.py``'s CONTAIN
    action narrates "isolate + kill + quarantine" in its human-readable
    reason text, but no ``quarantine_file`` responder exists anywhere in
    ``valkyrie/edr/response.py`` — only isolate_host and kill_process are
    real. The prose describes a control that was never built. Left
    unbuilt here too (quarantine is exactly the kind of new destructive
    action this audit's hard safety rules say not to add casually), but
    now it is a tracked, visible gap instead of an invisible one.

This is a classification of MECHANISMS, not of every Python file — plumbing
modules (store.py, eventbus.py, config.py, telemetry.py's schema) aren't
"controls" any more than a database driver is. ``CONTROLS`` below covers
every module whose job is a direct security or privacy effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PREVENTIVE   = "preventive"
DETECTIVE    = "detective"
CORRECTIVE   = "corrective"
DETERRENT    = "deterrent"
COMPENSATING = "compensating"
DIRECTIVE    = "directive"
RECOVERY     = "recovery"

CATEGORIES = (PREVENTIVE, DETECTIVE, CORRECTIVE, DETERRENT,
              COMPENSATING, DIRECTIVE, RECOVERY)

_DESCR = {
    PREVENTIVE:   "stops a harmful event before it completes",
    DETECTIVE:    "notices/records that something happened",
    CORRECTIVE:   "acts, after detection, to stop or remediate an incident",
    DETERRENT:    "discourages an attacker even before any control fires",
    COMPENSATING: "substitutes for a primary control that is unavailable",
    DIRECTIVE:    "policy/configuration that governs what other controls do",
    RECOVERY:     "restores normal state after a control fired or an incident",
}


@dataclass(frozen=True)
class Control:
    name: str                       # short id, usually the module name
    module: str                     # dotted path under valkyrie/
    category: str                   # primary IIBA §4.2.3 class
    secondary: tuple = field(default_factory=tuple)
    note: str = ""                  # what it does, in this specific role


CONTROLS: list[Control] = [
    # -- preventive: stop it before it happens -------------------------------
    Control("dns_sinkhole", "valkyrie.dns_interceptor", PREVENTIVE,
            note="applies the block/allow/deceive decision before a DNS "
                 "answer ever reaches the requesting process"),
    Control("firewall", "valkyrie.firewall", PREVENTIVE,
            note="standing DoH-resolver + threat-intel CIDR kernel/DNS-answer "
                 "blocking, always on, not incident-triggered"),
    Control("blocklist", "valkyrie.blocklist", PREVENTIVE,
            note="tracker/ad domain blocklist consulted on every query"),
    Control("seed_blocklist", "valkyrie.seed_blocklist", PREVENTIVE,
            note="offline day-one blocklist so preventive blocking works "
                 "with zero network access"),
    Control("tls_inspector", "valkyrie.tls_inspector", PREVENTIVE,
            secondary=(DETECTIVE,),
            note="intercepts/blocks/strips malicious HTTPS content in-flight"),
    Control("secure_file", "valkyrie.secure_file", PREVENTIVE,
            note="hardens secret file ACLs (CA key, MAC install key) before "
                 "they can be read by an unprivileged principal"),
    Control("telemetry_killer", "valkyrie.telemetry_killer", PREVENTIVE,
            secondary=(RECOVERY,),
            note="disables OS-level tracking at the source; restore() gives "
                 "it its own recovery path (see reversibility.py precedent)"),
    Control("mac_randomizer", "valkyrie.mac_randomizer", PREVENTIVE,
            secondary=(RECOVERY,),
            note="unlinkable MAC addresses prevent cross-network tracking; "
                 "restore() is its recovery path (see reversibility.py)"),
    Control("farble", "valkyrie.farble", PREVENTIVE,
            note="per-origin fingerprint randomisation prevents stable "
                 "browser fingerprinting from succeeding"),
    Control("persona", "valkyrie.persona", PREVENTIVE,
            note="feeds trackers a consistent FALSE identity instead of a "
                 "detectable non-answer, preventing 'runs a blocker' profiling"),
    Control("amsi_scan", "valkyrie.amsi", DETECTIVE,
            note="asks the OS antimalware engine for a real verdict on "
                 "content; a verdict-generator feeding EDR correlation, not "
                 "itself an execution gate"),

    # -- detective: notice it happened ---------------------------------------
    Control("behavioral_scoring", "valkyrie.behavioral", DETECTIVE,
            note="scores every DNS query on entropy/reputation/context axes"),
    Control("behavioral_rules", "valkyrie.behavioral_rules", DETECTIVE,
            note="IOA content-matching rule engine (CrowdStrike-style)"),
    Control("behavioral_sequences", "valkyrie.behavioral_sequences", DETECTIVE,
            note="named multi-step attack-sequence IOAs (ESP-style)"),
    Control("dga_detector", "valkyrie.dga", DETECTIVE,
            note="corroborated offline DGA domain detection"),
    Control("dns_tunnel_detector", "valkyrie.dns_tunnel", DETECTIVE,
            note="unique-subdomain flood analysis for exfiltration (T1048.003)"),
    Control("doh_bypass_detector", "valkyrie.doh_detector", DETECTIVE,
            note="flags live connections to hardcoded DoH resolver IPs"),
    Control("cname_uncloak", "valkyrie.cname_uncloak", DETECTIVE,
            note="resolves CNAME chains to see through tracker cloaking"),
    Control("threat_intel", "valkyrie.threat_intel", DETECTIVE,
            note="matches traffic against downloaded IOC feeds"),
    Control("site_analyzer", "valkyrie.site_analyzer", DETECTIVE,
            note="reads page content/behaviour, not just the domain name"),
    Control("site_scanner", "valkyrie.site_scanner", DETECTIVE,
            note="positive-signal-only real-time tracker detection"),
    Control("content_watch", "valkyrie.content_watch", DETECTIVE,
            note="continuous background page-content analysis"),
    Control("process_telemetry", "valkyrie.process_telemetry", DETECTIVE,
            secondary=(COMPENSATING,),
            note="userland psutil process-table poller; ALSO the "
                 "compensating control for Sysmon (see COMPENSATING below)"),
    Control("process_watcher", "valkyrie.process_watcher", DETECTIVE,
            note="attributes a DNS query's UDP socket back to a process"),
    Control("network_telemetry", "valkyrie.network_telemetry", DETECTIVE,
            note="flags outbound connections to threat-intel IPs that "
                 "never went through DNS"),
    Control("persistence_telemetry", "valkyrie.persistence_telemetry", DETECTIVE,
            note="watches ASEPs (run keys/services/tasks/startup folder) "
                 "for new autostart entries"),
    Control("asset_inventory", "valkyrie.asset_inventory", DETECTIVE,
            note="CIS Controls #1/#2: snapshot+diff of installed software, "
                 "listening ports, and kernel drivers; the delta feeds "
                 "correlation the same weak/INFO-only way process_telemetry."
                 "classify_discovery's labels do -- never a standalone "
                 "incident on its own"),
    Control("browser_cred_watch", "valkyrie.browser_cred_watch", DETECTIVE,
            note="flags non-browser processes touching a saved-password store"),
    Control("etw_sysmon", "valkyrie.etw.sysmon", DETECTIVE,
            note="real-time kernel-adjacent process/injection/LSASS/registry "
                 "telemetry — Valkyrie's richest, most-depended-on sensor"),
    Control("etw_powershell", "valkyrie.etw.powershell", DETECTIVE,
            note="PowerShell script-block content sensor"),
    Control("etw_wmi", "valkyrie.etw.wmi", DETECTIVE,
            note="WMI event-subscription persistence sensor"),
    Control("etw_wineventlog", "valkyrie.etw.wineventlog", DETECTIVE,
            note="Windows Event Log-backed sensor"),
    Control("native_process", "valkyrie.etw.native_process", DETECTIVE,
            note="native process-creation sensor"),
    Control("kernel_bridge", "valkyrie.kernel_bridge", DETECTIVE,
            note="talks to the (currently unsigned, not-for-production) "
                 "kernel driver telemetry channel"),
    Control("sensor_tamper", "valkyrie.sensor_tamper", DETECTIVE,
            note="meta-detective: notices Valkyrie's OWN sensors going dark "
                 "(T1562.001) — also drives the compensating-control hook"),
    Control("killchain_correlator", "valkyrie.edr.killchain", DETECTIVE,
            note="multi-stage kill-chain correlation across detections"),
    Control("threat_hunter", "valkyrie.edr.hunt", DETECTIVE,
            note="structured/saved-query threat hunting over collected telemetry"),
    Control("investigator", "valkyrie.edr.investigate", DETECTIVE,
            note="offline/AI-assisted incident investigation summaries"),
    Control("network_score", "valkyrie.network_score", DETECTIVE,
            note="composite network-risk scoring"),
    Control("behavior_score", "valkyrie.behavior_score", DETECTIVE,
            note="composite process-behaviour scoring"),
    Control("ransomware_canaries", "valkyrie.ransomware_shield", DETECTIVE,
            secondary=(CORRECTIVE, DETERRENT),
            note="canary tripwires detect mass-encryption; see CORRECTIVE "
                 "for the kill/suspend response and DETERRENT below"),

    # -- corrective: act, after detection, to stop/remediate -----------------
    Control("kill_process", "valkyrie.edr.response.KillProcessResponder",
            CORRECTIVE,
            note="terminates a process on a confirmed incident — "
                 "IRREVERSIBLE, gated at 'critical' severity (see "
                 "reversibility.py)"),
    Control("isolate_host", "valkyrie.edr.response.IsolateHostResponder",
            CORRECTIVE, secondary=(RECOVERY,),
            note="network-contains the endpoint; release_isolation is its "
                 "own recovery action (full state snapshot/restore)"),
    Control("remove_persistence",
            "valkyrie.edr.response.RemovePersistenceResponder", CORRECTIVE,
            note="rips out an attacker-created autostart entry after detection"),
    Control("block_domain", "valkyrie.edr.response.BlockDomainResponder",
            CORRECTIVE,
            note="durably blocks a domain confirmed malicious by an incident "
                 "(distinct from the standing PREVENTIVE blocklist)"),
    Control("ransomware_response", "valkyrie.ransomware_shield", CORRECTIVE,
            note="suspends (default) or kills the encrypting process once a "
                 "canary trips and entropy confirms real encryption"),
    Control("playbook_automation", "valkyrie.edr.playbooks", CORRECTIVE,
            secondary=(DIRECTIVE,),
            note="executes the corrective actions above automatically per "
                 "policy — the automation itself is directive (see below), "
                 "its effect is corrective"),

    # -- deterrent: discourage the attacker, not just catch them -------------
    Control("decoys", "valkyrie.decoys", DETERRENT, secondary=(DETECTIVE,),
            note="THE finding: honeytoken bait planted specifically so an "
                 "intruder announces themselves — deterrent value (raises an "
                 "attacker's perceived risk of discovery) was never named, "
                 "only its detective side-effect was"),

    # -- compensating: substitute for a lost primary control -----------------
    Control("sysmon_compensation", "valkyrie.process_telemetry.ProcessCollector",
            COMPENSATING,
            note="on Sysmon healthy->unhealthy (sensor_tamper.py), actively "
                 "tightens this poller's interval 4x as a partial substitute "
                 "for lost process-creation visibility. Does NOT compensate "
                 "for what only Sysmon sees: process injection (EID 8), "
                 "LSASS access (EID 10), unsigned module loads (EID 7), or "
                 "autorun registry writes (EID 13) — there is no userland "
                 "equivalent for any of those. This is the ONLY compensating "
                 "control in Valkyrie; no other primary sensor (DNS "
                 "interceptor, firewall, TLS inspector) has one."),

    # -- directive: policy that governs what the other controls do -----------
    Control("user_rules", "valkyrie.rules", DIRECTIVE,
            note="operator-authored always_allow/always_block policy"),
    Control("risk_profiles", "valkyrie.profiles", DIRECTIVE,
            note="selects the operating posture (standard/high_risk/travel/"
                 "clean_room) the decision policy reads"),
    Control("decision_policy", "valkyrie.decision", DIRECTIVE,
            note="maps a signal + profile to an Action (ALLOW/DECEIVE/BLOCK/"
                 "CONTAIN); its own prose currently over-promises a "
                 "'quarantine' step that has no responder behind it — see "
                 "module docstring above"),
    Control("playbook_policy", "valkyrie.edr.playbooks", DIRECTIVE,
            note="the YAML policy document itself (min_severity/mode/"
                 "cooldown) — see playbook_automation under CORRECTIVE for "
                 "its effect"),

    # -- recovery: restore normal state after a control fired ----------------
    Control("restore_persistence",
            "valkyrie.edr.response.RestorePersistenceResponder", RECOVERY,
            note="undoes remove_persistence from its pre-delete snapshot "
                 "(registry_run_key/startup_folder/scheduled_task only)"),
    Control("release_isolation", "valkyrie.edr.response.IsolateHostResponder",
            RECOVERY, secondary=(CORRECTIVE,),
            note="restores the exact pre-isolation firewall snapshot"),
    Control("mac_restore", "valkyrie.mac_randomizer.MacRandomizer.restore",
            RECOVERY,
            note="restores the original hardware MAC from backup"),
    Control("telemetry_restore", "valkyrie.telemetry_killer.TelemetryKiller.restore",
            RECOVERY,
            note="restores OS telemetry registry values from backup"),
]


def by_category() -> dict:
    """{category: [Control, ...]} for every CATEGORIES entry, including
    empty lists — an empty category must be visible, not absent."""
    out = {cat: [] for cat in CATEGORIES}
    for ctl in CONTROLS:
        out[ctl.category].append(ctl)
        for sec in ctl.secondary:
            out[sec].append(ctl)
    return out


def gaps() -> list:
    """Categories with NO primary member (secondary-only doesn't count --
    a category populated only by other categories' side-effects is still
    a gap in what that category is FOR). Returns [] if none."""
    primary_counts = {cat: 0 for cat in CATEGORIES}
    for ctl in CONTROLS:
        primary_counts[ctl.category] += 1
    return [cat for cat in CATEGORIES if primary_counts[cat] == 0]


def summary() -> str:
    lines = ["Valkyrie control taxonomy (IIBA §4.2.3)", ""]
    grouped = by_category()
    for cat in CATEGORIES:
        entries = grouped[cat]
        primaries = [c for c in entries if c.category == cat]
        lines.append(f"{cat.upper()} ({_DESCR[cat]}) — {len(primaries)} control(s)")
        if not primaries:
            lines.append("  ** GAP — no primary control in this category **")
        for c in entries:
            tag = "" if c.category == cat else " [secondary]"
            lines.append(f"  - {c.name}{tag}: {c.note}")
        lines.append("")
    empty = gaps()
    if empty:
        lines.append(f"Empty categories: {', '.join(empty)}")
    return "\n".join(lines)
