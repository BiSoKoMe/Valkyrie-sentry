"""The behavior translation / canonicalization boundary.

Every upstream detector -- behavioral_rules.py (144 rule-specific labels
across 173 rules), process_telemetry.py, behavior_score.py,
persistence_telemetry.py, network_telemetry.py, etw/powershell.py,
etw/sysmon.py -- speaks its own label vocabulary, because each one was
written independently to recognize one specific shape of evidence. Detection
Architecture v2's BehaviorEngine was written against a small, different,
hand-picked vocabulary (``lolbin``, ``office_child_shell``, ...). The gap
between those two vocabularies is why 39 of 50 real Tier A rule-fires
produced zero v2 evidence (see docs/TIER_A_V2_PIPELINE_TRACE.md) -- not a
telemetry problem and not a reasoning problem, an untranslated-language
problem between two correct subsystems.

This module is the fix: ONE canonical behavior vocabulary that every
upstream label translates into, so BehaviorEngine reasons about reusable
security semantics (``credential_access_attempt``, ``lolbin_proxy_execution``,
...) instead of 190+ one-off rule names. Adding rule #174 to
behavioral_rules.py should never require touching this file UNLESS it
represents a genuinely new semantic category -- extending the label->
canonical map for a same-shape label is the expected, low-friction case.

This module does exactly one thing: translate labels. It does not decide
severity, does not decide alerts, and does not touch detection_v2's
hypothesis thresholds. Every label in the codebase that reaches this module
is accounted for -- mapped to a canonical behavior, or named in
`UNMAPPED_KNOWN_LABELS` with a documented reason it is intentionally left
out. Nothing is silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# THE CANONICAL VOCABULARY
#
# Each name is a reusable security semantic, not a rule name -- the whole
# point per the "next plan" essay: rule_A / rule_B / rule_C -> one canonical
# UNEXPECTED_PROCESS_RELATIONSHIP, not if rule_37: emit behavior_37.
# `unexpected_process_relationship`, `sensitive_configuration_modified`, and
# `external_communication` already existed in detection_v2.BehaviorEngine;
# the rest are new categories this module introduces to cover the real
# vocabulary gap the Tier A trace found.
# ---------------------------------------------------------------------------
CANONICAL_BEHAVIORS = frozenset({
    "unexpected_process_relationship",   # anomalous execution origin/ancestry
    "sensitive_configuration_modified",  # a durable, security-relevant state change
    "external_communication",            # a process talked to an external destination
    "security_control_tampering",        # defense evasion aimed at Valkyrie/AV/logging
    "credential_access_attempt",         # credential theft/dumping/enumeration
    "discovery_activity",                # host/domain/account reconnaissance
    "lateral_movement",                  # remote-execution / lateral tooling
    "code_injection",                    # process/memory injection primitives
    "obfuscated_execution",              # encoding/obfuscation of what is executing
    "lolbin_proxy_execution",            # a trusted OS binary proxying execution/fetch
    "destructive_impact",                # data destruction / recovery inhibition
    "collection_staging",                # staging or archiving data for exfiltration
})

# Benign/counter-evidence labels are NOT security behaviors -- they explain
# why one might legitimately look suspicious. Kept as their own small set so
# canonicalize() never accidentally treats "this is trusted" as an attack
# signal. `known_admin` and `expected_maintenance` are declared here for
# documentation purposes only: no producer in this codebase emits them today
# (checked directly against every module below) -- an honest, named gap
# rather than a mapping pretending to have a source.
TRUST_LABELS = frozenset({
    "trusted", "trusted_os_path", "signed", "known_admin", "expected_maintenance",
    # persistence_telemetry.py's own name for the same "trusted OS autostart
    # target" concept asset_inventory.py calls trusted_os_path -- same
    # semantic, different producer, both benign counter-evidence.
    "trusted_os",
})


@dataclass(frozen=True)
class Canonicalization:
    """The result of translating one event's raw labels."""
    hit: tuple[str, ...]              # canonical behaviors present
    trust: tuple[str, ...]            # benign/counter-evidence labels present
    provenance: dict                  # canonical behavior -> raw label(s) that produced it
    unmapped: tuple[str, ...]         # raw labels with no known mapping at all


# ---------------------------------------------------------------------------
# THE TRANSLATION TABLE
#
# Grouped by source module and MITRE tactic shape, built from the actual
# label sets emitted today (verified against RULES in behavioral_rules.py,
# and the labels.append(...)/Signal(...) call sites in process_telemetry.py,
# behavior_score.py, persistence_telemetry.py, network_telemetry.py,
# etw/powershell.py, etw/sysmon.py -- not guessed from label names alone).
# ---------------------------------------------------------------------------

# -- unexpected_process_relationship: anomalous execution origin/ancestry --
_UNEXPECTED_PROCESS_RELATIONSHIP = frozenset({
    # process_telemetry.py
    "office_child_shell", "lolbin", "suspicious_path", "hidden_window",
    # behavioral_rules.py
    "scripthost_document_child", "scripthost_dropzone", "unsigned_drop_zone",
    "trusted_dev_exec", "masquerade_syspath", "masquerade_system_binary",
    "signature_untrusted", "wsl_exec",
    # behavior_score.py (the generalizing anomaly nose)
    "wrong_parent_system_proc", "system_proc_spawned_shell",
    "server_spawned_shell", "document_spawned_interpreter",
    "exec_from_lowtrust", "interpreter_from_lowtrust", "payload_from_lowtrust",
    "masquerade_system_image", "system_name_lookalike", "double_extension",
    "bidi_filename_trick", "machine_generated_name", "padded_name_masquerade",
    "rare_ancestry_for_host",
    # etw/sysmon.py -- a driver load or unsigned module is an unusual
    # execution-origin signal on its own; BYOVD's more specific "used to
    # disable security tooling" shape is under security_control_tampering.
    "driver_load", "unsigned_module",
})

# -- sensitive_configuration_modified: a durable security-relevant change --
_SENSITIVE_CONFIGURATION_MODIFIED = frozenset({
    # persistence_telemetry.py canonical activity labels
    "persistence_run_key", "persistence_service", "persistence_scheduled_task",
    "persistence_startup_folder",
    # behavioral_rules.py persistence rules (fire as process-category hits,
    # not necessarily through the persistence collector -- this is exactly
    # why event_type==PERSISTENCE alone was an incomplete gate)
    "persistence_runkey", "persistence_startup", "persistence_service_reg",
    "persistence_scheduled_task", "persistence_task", "persistence_at",
    "persistence_wmi", "persistence_mof", "persistence_com",
    "persistence_ifeo", "persistence_appinit", "persistence_asep_dll",
    "persistence_lsa", "persistence_logon_script", "persistence_netsh",
    "persistence_ps_profile", "persistence_screensaver", "persistence_winlogon",
    "persistence_corprofiler", "persistence_bits",
    # account / boot / firewall / RDP / ACL / UAC state changes
    "account_created", "account_manip", "boot_tamper", "rdp_enabled",
    "firewall_allow", "mass_acl_change", "uac_bypass", "uac_bypass_reg",
    "credential_access_setup",
    # persistence_telemetry._persistence_severity's generic fallback label
    # when the activity string isn't one of the four named PERSIST_* kinds --
    # still a genuine new-autostart-entry signal, just not one of the named
    # sub-kinds, so it belongs in the same canonical behavior, not unmapped.
    "persistence",
})

# -- external_communication: a process reached an external destination --
_EXTERNAL_COMMUNICATION = frozenset({
    "threat_intel_ip",   # network_telemetry.py
    "c2_tunnel", "port_forward", "cloud_exfil", "exfiltration", "ingress_curl",
    "certutil_download", "download_cradle", "bitsadmin_transfer",
    "lolbin_mpcmdrun", "lateral_tool_transfer",
    "lolbin_network_fetch",   # behavior_score.py
    "download",               # etw/powershell.py
    # sysmon's generic "outbound" carries no more information than the
    # event's own category=NETWORK already gives BehaviorEngine (which fires
    # external_communication unconditionally on DNS/NETWORK events) -- listed
    # here for completeness, not because it adds signal on its own.
    "outbound",
})

# -- security_control_tampering: defense evasion against the security stack --
_SECURITY_CONTROL_TAMPERING = frozenset({
    "amsi_bypass", "defender_tamper", "evade_ps_downgrade", "impair_av_defs",
    "impair_defenses", "impair_etw", "impair_telemetry_reg", "impair_audit",
    "logging_tamper", "eventlog_cleared", "clear_eventlog_ps",
    "indicator_removal", "usn_deleted", "sensor_uninstall", "sensor_unload",
    "safe_mode_boot", "security_service_stop", "firewall_disabled",
    # etw/powershell.py + etw/sysmon.py
    "defender_tamper", "byovd",
})

# -- credential_access_attempt: credential theft/dumping/enumeration --
_CREDENTIAL_ACCESS_ATTEMPT = frozenset({
    "lsass_access", "lsass_dump", "credential_dumping", "credential_copy",
    "cred_tool", "cred_browser", "cred_hunt", "cred_ps_history",
    "cred_store_list", "cred_wifi", "credential_store_access",
    "collection_archive_creds", "collection_copy_creds", "sam_dump",
    "ntds_dump", "ntds_file_theft", "kerberoasting", "kerberoast_recon",
    "pass_the_hash", "stored_cred_abuse", "vault_enum",
    "credential_access",   # etw/powershell.py
})

# -- discovery_activity: host/domain/account reconnaissance --
_DISCOVERY_ACTIVITY = frozenset({
    "domain_discovery", "user_discovery",
})

# -- lateral_movement: remote-execution / lateral tooling --
_LATERAL_MOVEMENT = frozenset({
    "lateral_psexec", "lateral_wmic", "lateral_dcom", "lateral_winrm",
    "lateral_winrs", "psexec_system",
})

# -- code_injection: process/memory injection primitives --
_CODE_INJECTION = frozenset({
    "dll_injection", "reflective_load", "inmemory_compile",
    "remote_thread_injection", "process_tampering",   # etw/sysmon.py
    "injection_primitive",                             # etw/powershell.py
})

# -- obfuscated_execution: encoding/obfuscation of what is executing --
_OBFUSCATED_EXECUTION = frozenset({
    "encoded_powershell", "obfuscated_exec", "certutil_decode",
    "clickfix_paste_exec", "fileless_cradle", "execpolicy_bypass",
    "hidden_exec", "hide_file",
    # etw/powershell.py
    "encoded_command", "base64_decode", "obfuscation", "stealth_flags",
    "dynamic_exec",   # IEX-style indirect/dynamic code execution
    # behavior_score.py
    "obfuscated_command",
})

# -- lolbin_proxy_execution: a trusted OS binary proxying execution/fetch --
_LOLBIN_PROXY_EXECUTION = frozenset({
    "mshta_exec", "regsvr32_scriptlet", "rundll32_proxy", "wmic_xsl_exec",
    "wmi_process_create", "wmic_process_call",
    "lolbin_chm_exec", "lolbin_cimprovider", "lolbin_copy", "lolbin_dll_exec",
    "lolbin_dnscmd", "lolbin_dotnet_exec", "lolbin_inf", "lolbin_inf_exec",
    "lolbin_msdt_exec", "lolbin_msxsl", "lolbin_proxy_exec",
    "lolbin_remote_msi", "lolbin_script_proxy", "lolbin_scriptrunner",
    "lolbin_xbap_exec", "lolbin_xwizard",
    "script_proxy_remote",   # behavior_score.py
    # persistence_task (etw/powershell.py) is scheduled-task creation FROM a
    # script block -- that's sensitive_configuration_modified, not a proxy
    # execution shape; kept there, not duplicated here.
})

# -- destructive_impact: data destruction / recovery inhibition --
_DESTRUCTIVE_IMPACT = frozenset({
    "destroy_files", "disk_format", "freespace_wipe", "secure_wipe",
    "backup_delete", "shadow_delete", "shadow_manipulation",
    "inhibit_recovery", "inhibit_recovery_reg", "recovery_disabled",
})

# -- collection_staging: staging or archiving data for exfiltration --
_COLLECTION_STAGING = frozenset({
    "collection_archive", "ad_bulk_export", "capture_netsh", "capture_pktmon",
})

_CANONICAL_TABLE: dict[str, frozenset[str]] = {
    "unexpected_process_relationship": _UNEXPECTED_PROCESS_RELATIONSHIP,
    "sensitive_configuration_modified": _SENSITIVE_CONFIGURATION_MODIFIED,
    "external_communication": _EXTERNAL_COMMUNICATION,
    "security_control_tampering": _SECURITY_CONTROL_TAMPERING,
    "credential_access_attempt": _CREDENTIAL_ACCESS_ATTEMPT,
    "discovery_activity": _DISCOVERY_ACTIVITY,
    "lateral_movement": _LATERAL_MOVEMENT,
    "code_injection": _CODE_INJECTION,
    "obfuscated_execution": _OBFUSCATED_EXECUTION,
    "lolbin_proxy_execution": _LOLBIN_PROXY_EXECUTION,
    "destructive_impact": _DESTRUCTIVE_IMPACT,
    "collection_staging": _COLLECTION_STAGING,
}

# Reverse index for O(1) lookup, built once at import time. Two canonical
# behaviors deliberately never share a raw label -- verified by the test
# suite (test_behavior_ontology.py) rather than only by inspection.
_LABEL_TO_CANONICAL: dict[str, str] = {
    label: canonical
    for canonical, labels in _CANONICAL_TABLE.items()
    for label in labels
}

# Raw labels seen in the codebase that are DELIBERATELY not mapped to a
# canonical behavior, with the reason on record -- so a label missing from
# canonicalize()'s output is a documented decision, never an oversight.
UNMAPPED_KNOWN_LABELS: dict[str, str] = {
    # detection_v2's own existing benign-trust vocabulary -- handled by
    # TRUST_LABELS, not a canonical attack behavior.
    "trusted": "benign counter-evidence, see TRUST_LABELS",
    "trusted_os_path": "benign counter-evidence (asset_inventory.py), see TRUST_LABELS",
    "signed": "benign counter-evidence, see TRUST_LABELS",
    "known_admin": "benign counter-evidence placeholder in detection_v2._TRUST_LABELS "
                   "with NO current producer anywhere in this codebase -- an honest "
                   "existing gap, not something this module can map to a source.",
    "expected_maintenance": "same as known_admin: declared in detection_v2._TRUST_LABELS, "
                            "no current producer.",
    # already handled as their own dedicated BehaviorEngine check, not part
    # of the canonical-behavior/trust split.
    "trusted_gesture": "handled directly by BehaviorEngine as active_user_context, "
                       "outside this table by design.",
    "user_initiated": "handled directly by BehaviorEngine as active_user_context, "
                      "outside this table by design.",
    # Provenance marker, not a behavior. No rule in behavioral_rules.RULES has
    # this as its OWN label (verified: zero rules with label=="sigma_import");
    # it is appended at match time alongside a real semantic label to mark a
    # hit as coming from the imported Sigma content funnel. Excluding it never
    # loses evidence -- the rule's other, real label is what canonicalizes.
    "sigma_import": "import-provenance marker on Sigma-derived rule hits; "
                    "always accompanies a real semantic label, never appears alone.",
}


def canonicalize(labels) -> Canonicalization:
    """Translate one event's raw labels into canonical behaviors.

    Never invents a mapping to force a match: a label absent from both the
    canonical table and UNMAPPED_KNOWN_LABELS comes back in `.unmapped`,
    visible and countable, exactly so a real integration gap can be measured
    instead of hidden.
    """
    hit: list[str] = []
    trust: list[str] = []
    provenance: dict[str, list[str]] = {}
    unmapped: list[str] = []

    for label in labels:
        if label in TRUST_LABELS:
            trust.append(label)
            continue
        canonical = _LABEL_TO_CANONICAL.get(label)
        if canonical is not None:
            if canonical not in hit:
                hit.append(canonical)
            provenance.setdefault(canonical, []).append(label)
            continue
        if label in UNMAPPED_KNOWN_LABELS:
            continue   # documented as intentionally non-canonical, not a gap
        unmapped.append(label)

    return Canonicalization(
        hit=tuple(hit), trust=tuple(dict.fromkeys(trust)),
        provenance={k: tuple(v) for k, v in provenance.items()},
        unmapped=tuple(dict.fromkeys(unmapped)),
    )
