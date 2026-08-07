"""Incident impact — plain language, not a fabricated score.

Clinton's *Cybersecurity for Business* (ch. 4) makes a specific, empirical
claim: colors, letter grades, and 0-100 scores are not decision-useful —
they FEEL precise while hiding the one thing a person actually needs to
decide what to do, which is "what did this cost me and can I undo it."
IIBA/IEEE's *Cybersecurity Analysis* handbook (§4.9.4) points at NIST SP
800-30's adverse-impact vocabulary as the alternative worth reusing rather
than inventing a new one.

NIST SP 800-30 (Guide for Conducting Risk Assessments) defines impact
across several rows — harm to operations, harm to assets, harm to
individuals, harm to other organizations, harm to the nation. Valkyrie
protects one person's endpoint: there is no organization, no mission
operations, no nation-level stake here, so exactly one row applies —
**Harm to Individuals** — described in terms of identity theft, loss of
PII, and damage to reputation/standing. This module does not reproduce
NIST's tables verbatim (a US government publication with its own precise
wording); it reuses the CATEGORY of harm it names, applied honestly to
what Valkyrie's detectors can actually see.

**What this module refuses to do, on purpose:**
  * No dollar figures. Clinton's own point is that a number that LOOKS
    precise but isn't (a $47,000 "estimated cost" with no real basis) is
    worse than an honest qualitative statement — it borrows credibility
    the estimate hasn't earned.
  * No claim of CONFIRMED exposure when Valkyrie only observed an ATTEMPT.
    Blocking an exfiltration attempt and confirming data actually left the
    machine are different facts; conflating them either overstates harm
    (alarm fatigue) or, worse, understates a genuine breach.

``severity`` (schema.py's SEVERITIES) is left completely alone — playbook
matching and correlation still key off it. This module adds ``impact`` as
what a HUMAN reads; severity stays what the MACHINE reads.
"""

from __future__ import annotations

from dataclasses import dataclass

# NIST SP 800-30 harm-to-individuals tiers, named not numbered.
HARM_LOW      = "low"          # limited/inconvenience-level effect
HARM_MODERATE = "moderate"     # significant harm (e.g. PII exposure risk)
HARM_HIGH     = "high"         # severe harm (e.g. credential theft, extortion)
HARM_UNKNOWN  = "unknown"      # Valkyrie cannot characterize harm from what it saw

HARM_LEVELS = (HARM_LOW, HARM_MODERATE, HARM_HIGH, HARM_UNKNOWN)


@dataclass(frozen=True)
class ImpactAssessment:
    harm_level: str          # one of HARM_LEVELS
    confirmed: bool          # True: Valkyrie verified exposure. False: attempt/risk only.
    exposed: str             # what was exposed or put at risk, in plain language
    to_whom: str             # who is affected
    reversible: str          # yes/no/partial + why, in plain language
    recommended_action: str  # what to do right now

    def to_dict(self) -> dict:
        return {
            "harm_level": self.harm_level,
            "confirmed": self.confirmed,
            "exposed": self.exposed,
            "to_whom": self.to_whom,
            "reversible": self.reversible,
            "recommended_action": self.recommended_action,
            "line": self.line(),
        }

    def line(self) -> str:
        """One sentence for a UI that only has room for one line."""
        verb = "confirmed" if self.confirmed else "attempted"
        return (f"{self.exposed} ({verb}, affects {self.to_whom}) — "
                f"{self.reversible}. {self.recommended_action}")


def _who(incident: dict) -> str:
    return "you (this device's user)"


def _entity_or(incident: dict, fallback: str) -> str:
    return incident.get("entity") or incident.get("process_name") or fallback


def _assess_decoy(incident: dict) -> ImpactAssessment:
    return ImpactAssessment(
        harm_level=HARM_HIGH, confirmed=True,
        exposed="a process accessed a planted decoy (fake password file, "
               "SSH key, or confidential document) — this is not a false "
               "positive by construction, only an intruder browsing the "
               "device would ever touch it",
        to_whom=_who(incident),
        reversible="not fully — an intruder with this kind of access may "
                   "already have copied real files before or after "
                   "touching the decoy; the access itself cannot be undone",
        recommended_action="stop sensitive work on this device now, keep it "
                           "powered on and connected for evidence, and "
                           "change passwords for accounts used on this "
                           "device from a DIFFERENT, trusted device",
    )


def _assess_sensor_tamper(incident: dict) -> ImpactAssessment:
    return ImpactAssessment(
        harm_level=HARM_MODERATE, confirmed=True,
        exposed="a detection sensor Valkyrie depends on stopped delivering "
               "events — nothing was necessarily stolen, but Valkyrie's "
               "ability to SEE further malicious activity is degraded",
        to_whom=_who(incident),
        reversible="depends on the cause — a legitimate conflict (another "
                   "security product) is fixable by adjusting that "
                   "product's settings; if this was intentional tampering, "
                   "the disabling itself is what needs reversing",
        recommended_action="check Sysmon/sensor status in the app; if no "
                           "other security software explains it, treat the "
                           "device as unmonitored until it's resolved",
    )


def _assess_credential_access(incident: dict) -> ImpactAssessment:
    proc = _entity_or(incident, "an unknown process")
    return ImpactAssessment(
        harm_level=HARM_HIGH, confirmed=False,
        exposed=f"'{proc}' attempted to read credential material "
               f"(saved passwords, or memory that can contain login "
               f"credentials) — this is the technique behind account "
               f"takeover and identity theft",
        to_whom=_who(incident),
        reversible="the ATTEMPT is stopped, but if it succeeded before "
                   "detection, any credentials it reached are compromised "
                   "and must be treated as stolen, not merely at-risk",
        recommended_action="change passwords for accounts stored in this "
                           "device's browsers from a DIFFERENT device, and "
                           "enable multi-factor authentication where you "
                           "haven't already",
    )


def _assess_injection(incident: dict) -> ImpactAssessment:
    proc = _entity_or(incident, "an unknown process")
    return ImpactAssessment(
        harm_level=HARM_HIGH, confirmed=False,
        exposed=f"'{proc}' showed process-injection behaviour — one "
               f"process manipulating another's memory, a technique used "
               f"to hide malicious code inside a trusted process",
        to_whom=_who(incident),
        reversible="the specific process was stopped, but injection is "
                   "often one step in a longer intrusion — treat the whole "
                   "device as suspect, not just this one process",
        recommended_action="run a full scan with your antivirus/Defender, "
                           "and avoid entering passwords or opening "
                           "sensitive files until it comes back clean",
    )


def _assess_ransomware(incident: dict) -> ImpactAssessment:
    return ImpactAssessment(
        harm_level=HARM_HIGH, confirmed=True,
        exposed="mass file encryption was detected in progress on this "
               "device — your files (documents, photos, everything the "
               "canary tripwires sit among) were the target",
        to_whom=_who(incident),
        reversible="the encrypting process was stopped/suspended, which "
                   "limits further damage, but ANY files already encrypted "
                   "before it was stopped are not decrypted by that alone "
                   "— check your files, and restore from backup if you "
                   "have one; Valkyrie does not hold a copy of your files",
        recommended_action="do not pay a ransom demand if one appears; "
                           "disconnect from shared drives/cloud sync so "
                           "encrypted copies don't propagate, and restore "
                           "affected files from your own backups",
    )


def _assess_exfiltration(incident: dict) -> ImpactAssessment:
    proc = _entity_or(incident, "an unknown process")
    return ImpactAssessment(
        harm_level=HARM_MODERATE, confirmed=False,
        exposed=f"'{proc}' showed signs of moving data off this device "
               f"through an unusual channel (e.g. hidden inside DNS "
               f"lookups) — the specific content is not something Valkyrie "
               f"can read, only that the channel and pattern match "
               f"exfiltration",
        to_whom=_who(incident),
        reversible="no — if data already left the device, it cannot be "
                   "recalled; blocking stops FURTHER loss, not what "
                   "already went out",
        recommended_action="review what sensitive files/credentials this "
                           "process could reach, and change any passwords "
                           "or keys it had access to",
    )


def _assess_persistence(incident: dict) -> ImpactAssessment:
    proc = _entity_or(incident, "an unknown program")
    return ImpactAssessment(
        harm_level=HARM_MODERATE, confirmed=True,
        exposed=f"'{proc}' installed itself to start automatically — this "
               f"is how malware survives a restart; nothing is necessarily "
               f"stolen yet, but the device now has an unwanted foothold",
        to_whom=_who(incident),
        reversible="yes, usually — removing the autostart entry (which "
                   "Valkyrie can do automatically) undoes the persistence "
                   "mechanism itself, though whatever it already did before "
                   "removal is separate",
        recommended_action="let Valkyrie remove the entry if it hasn't "
                           "already, and consider a full antivirus scan "
                           "since something installed this deliberately",
    )


def _assess_c2_beacon(incident: dict) -> ImpactAssessment:
    proc = _entity_or(incident, "a process")
    return ImpactAssessment(
        harm_level=HARM_MODERATE, confirmed=False,
        exposed=f"'{proc}' communicated with infrastructure that matches "
               f"known command-and-control / algorithmically-generated "
               f"domain patterns — a sign the device may be remotely "
               f"controlled",
        to_whom=_who(incident),
        reversible="the specific connection was blocked, but if control "
                   "was already established, that access itself needs to "
                   "be found and removed, not just this one connection",
        recommended_action="if this recurs after blocking, run a full "
                           "antivirus scan and consider the device "
                           "compromised until it comes back clean",
    )


def _assess_known_bad_contact(incident: dict) -> ImpactAssessment:
    entity = _entity_or(incident, "a known-bad domain/IP")
    return ImpactAssessment(
        harm_level=HARM_LOW, confirmed=False,
        exposed=f"this device contacted '{entity}', which is on a threat-"
               f"intelligence list — this alone does not confirm "
               f"compromise, many such contacts are ad/tracker noise, not "
               f"targeted attacks",
        to_whom=_who(incident),
        reversible="yes — the connection was blocked before completing",
        recommended_action="no action needed unless this repeats "
                           "frequently from the same process, which would "
                           "be worth a closer look",
    )


def _assess_tracking(incident: dict) -> ImpactAssessment:
    return ImpactAssessment(
        harm_level=HARM_LOW, confirmed=True,
        exposed="ordinary ad/tracker network activity — browsing habits "
               "and device identifiers used for advertising profiling, not "
               "credentials or files",
        to_whom=_who(incident),
        reversible="yes — blocked going forward; nothing to undo",
        recommended_action="none needed — this is what Valkyrie's tracker "
                           "blocking is routinely catching",
    )


def _assess_generic_process(incident: dict) -> ImpactAssessment:
    proc = _entity_or(incident, "a process")
    return ImpactAssessment(
        harm_level=HARM_LOW, confirmed=False,
        exposed=f"'{proc}' matched a behavioural rule Valkyrie flags for "
               f"review — not yet confirmed malicious",
        to_whom=_who(incident),
        reversible="yes — nothing has been taken automatically at this "
                   "severity; the activity was recorded and correlated",
        recommended_action="review the incident details; no action needed "
                           "unless it recurs or escalates",
    )


def _assess_unknown(incident: dict) -> ImpactAssessment:
    return ImpactAssessment(
        harm_level=HARM_UNKNOWN, confirmed=False,
        exposed="Valkyrie does not have a specific impact narrative for "
               "this incident's category yet — treat this as informational "
               "until reviewed",
        to_whom=_who(incident),
        reversible="unknown",
        recommended_action="review the incident's raw detections for "
                           "context",
    )


def assess(incident: dict) -> ImpactAssessment:
    """The single entry point: incident dict (EdrEngine.get_incident() shape,
    or any dict with category/technique/entity/process_name/details) -> the
    plain-language NIST-800-30-flavoured impact for a human to read.

    Dispatch order matters: more specific / higher-confidence signals are
    checked before generic category matching, mirroring how the correlation
    engine itself treats a decoy hit or a credential-access technique as a
    stronger signal than its raw category alone would suggest.
    """
    category = str(incident.get("category") or "").lower()
    technique = str(incident.get("technique") or "").lower()
    labels: list = []
    for det in incident.get("detections") or []:
        labels.extend((det.get("details") or {}).get("labels") or [])
    labels = [str(x).lower() for x in labels]

    if "decoy" in labels or category == "decoy":
        return _assess_decoy(incident)
    if "sensor_tamper" in labels or incident.get("entity") == "sysmon" \
            or "t1562.001" in technique:
        return _assess_sensor_tamper(incident)
    if technique.startswith("t1003") or "lsass_access" in labels \
            or "credential_access" in labels:
        return _assess_credential_access(incident)
    if technique.startswith("t1055") or "remote_thread_injection" in labels \
            or "injection_primitive" in labels or "process_tampering" in labels:
        return _assess_injection(incident)
    if category == "ransomware":
        return _assess_ransomware(incident)
    if category == "exfil" or technique.startswith("t1048"):
        return _assess_exfiltration(incident)
    if category == "persistence":
        return _assess_persistence(incident)
    if category in ("dga", "tunnel", "dyndns", "attack_chain", "attack_sequence") \
            or "c2" in labels:
        return _assess_c2_beacon(incident)
    if category in ("intelligence", "threat_intel", "firewall_ip"):
        return _assess_known_bad_contact(incident)
    if category in ("tracker", "behavioral", "anomaly", "doh_bypass"):
        return _assess_tracking(incident)
    if category in ("process", "malware", "network"):
        return _assess_generic_process(incident)
    return _assess_unknown(incident)
