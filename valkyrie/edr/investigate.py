"""AI-assisted investigation.

Turns a raw incident (a pile of correlated detections) into an analyst-style
writeup: what happened, why it matters, and what to do about it.

Two modes:

  * **Offline heuristic (default, always available).** A deterministic,
    fully-local analyst built from the incident's own detections - severity
    rationale, observed MITRE techniques, affected process/entities, a timeline
    digest, and concrete recommended response actions. No network, no key.

  * **LLM-assisted (opt-in, off by default).** If - and only if - the operator
    explicitly enables it AND an AI provider is configured, the incident is
    summarised by an LLM for a richer narrative. The backend is vendor-neutral
    (see ``ai_provider.py`` - Anthropic, OpenAI, a local OpenAI-compatible
    server, or offline); this module never depends on a specific vendor. A
    network provider SENDS incident details (including domains) to the
    configured endpoint, so it is deliberately gated: it respects the same
    "opt-in, off by default, clearly disclosed" rule the platform roadmap sets
    for any telemetry that leaves the machine. Any error (no provider, network
    blocked) silently falls back to the offline analyst - the investigation
    always returns something useful. Use the ``local`` provider to keep
    everything on-box.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .ai_provider import AIProvider, get_provider
from .schema import Incident, severity_rank

# Category -> plain-English "what this means" for the offline analyst.
_MEANING = {
    "firewall_ip":  "A process resolved a domain that pointed at an IP address "
                    "on a threat-intelligence blocklist — this is the strongest "
                    "signal of active malware or command-and-control traffic.",
    "intelligence": "Valkyrie's self-learning engine matched this against threat "
                    "behaviour it has learned on this machine.",
    "behavioral":   "The hostname looks algorithmically generated (high entropy), "
                    "a hallmark of malware domain-generation algorithms.",
    "dga":          "The registrable domain is algorithmically generated — its "
                    "length, entropy, and implausible letter sequences all agree "
                    "— which is how malware families rendezvous with rotating "
                    "command-and-control infrastructure (T1568.002).",
    "doh_bypass":   "A process tried to tunnel its DNS over HTTPS to evade the "
                    "local filter — an active evasion attempt.",
    "anomaly":      "A process reached a destination outside its learned baseline "
                    "— unusual, though not necessarily malicious.",
    "tracker":      "Known advertising/tracking infrastructure was blocked — a "
                    "privacy signal rather than a compromise.",
    # Endpoint (telemetry-path) categories - CAT_PROCESS / CAT_PERSISTENCE /
    # CAT_NETWORK. These carry Valkyrie's most severe detections and previously
    # fell through to the generic fallback with no meaning and no recommended
    # action (see tests/test_explainability.py, the gate that now prevents this).
    "process":      "A process on this endpoint showed malicious behaviour — "
                    "reading LSASS memory, injecting into another process, or "
                    "executing from an untrusted location. Endpoint process "
                    "telemetry (ETW/Sysmon or the process collector) is the "
                    "evidence; treat as a likely hands-on-keyboard or malware step.",
    "persistence":  "An auto-start extension point was created — a registry Run "
                    "key, service, scheduled task, Startup-folder item, or WMI "
                    "event subscription — the mechanism an attacker uses to "
                    "survive reboot and re-establish a foothold.",
    "network":      "This endpoint made an outbound connection to infrastructure "
                    "on a threat-intelligence blocklist — a strong command-and-"
                    "control signal that DNS filtering alone cannot see because "
                    "the destination was reached by hard-coded IP.",
    "tunnel":       "A process streamed many unique, machine-generated subdomains "
                    "under one base in a short window — the shape of DNS tunnelling "
                    "used to exfiltrate data or carry C2 over DNS (T1048.003), a "
                    "pattern no single DNS query reveals.",
    "dyndns":       "A process resolved a generated-looking hostname on a wildcard "
                    "IP-echo DNS provider (e.g. nip.io) — a way to hide traffic "
                    "under a legitimate base domain that ordinary reputation checks "
                    "can't see (T1568 — Dynamic Resolution).",
    "attack_chain": "One actor crossed MULTIPLE independent ATT&CK tactics in a "
                    "short window (e.g. execution → command-and-control → "
                    "persistence) — the shape a real intrusion takes. How much "
                    "that's worth depends on the evidence behind it: how strong the "
                    "individual detections are, whether the process lineage was "
                    "directly observed or only guessed by name, and how tightly "
                    "clustered the stages were in time — see the confidence tier "
                    "below rather than assuming this category alone is decisive.",
    "malware":      "The operating system's antimalware provider CONVICTED this "
                    "content through AMSI — this is not a Valkyrie heuristic but "
                    "an external engine's verdict on the actual bytes, carrying a "
                    "signature corpus Valkyrie does not have. Treat it as the "
                    "strongest single-event evidence available on this endpoint. "
                    "Note the converse does not hold: content the provider did "
                    "not convict is not thereby clean.",
    "attack_sequence": "One lineage completed a SPECIFIC, named attack pattern in "
                    "order (e.g. process injection → credential access, or recovery "
                    "inhibition → mass encryption) within a short window — a stateful "
                    "event-stream IOA. Unlike the generic multi-tactic chain, this "
                    "names the exact tradecraft observed, tool-agnostically, so "
                    "confidence is high and the response is specific.",
}

# Category -> which response actions the analyst recommends, in priority order.
# Every action here MUST be a shipped responder in edr/response.py
# (block_domain, kill_process, isolate_host) - never an aspirational one.
_RECOMMEND = {
    "firewall_ip":  ["isolate_host", "kill_process", "block_domain"],
    "intelligence": ["block_domain", "kill_process"],
    "behavioral":   ["block_domain"],
    "dga":          ["block_domain", "kill_process"],
    "doh_bypass":   ["kill_process", "block_domain"],
    "anomaly":      ["block_domain"],
    "tracker":      ["block_domain"],
    # Endpoint categories: contain the host first, then stop the offending
    # process. (block_domain is omitted for `network` because its entity is an
    # IP, which the domain responder does not enforce.)
    "process":      ["isolate_host", "kill_process"],
    "persistence":  ["kill_process", "isolate_host"],
    "network":      ["isolate_host", "kill_process"],
    "tunnel":       ["block_domain", "isolate_host"],
    "dyndns":       ["block_domain"],
    # A provider conviction is the highest-confidence endpoint evidence there
    # is: stop the process running the content, then contain the host.
    "malware":      ["kill_process", "isolate_host"],
    # A confirmed multi-stage chain is the strongest reason to contain the
    # host outright, then stop the offending process.
    "attack_chain": ["isolate_host", "kill_process", "block_domain"],
    # A named behavioural sequence is a specific, high-confidence attack -
    # contain the host and kill the offending process.
    "attack_sequence": ["isolate_host", "kill_process", "block_domain"],
}

# Category -> the SAME meaning as _MEANING above, in plain language for a
# person who has never heard of AMSI, LSASS, or ATT&CK technique IDs. _MEANING
# stays intact as the technical layer an analyst can still inspect; this is
# the layer a normal person actually reads. Deliberately a separate map
# rather than a rewrite of _MEANING, so nothing already tested changes shape.
_PLAIN_WHY = {
    "firewall_ip":  "This device tried to reach an address that's already known "
                    "to be used by attackers — one of the strongest signals "
                    "something is actively wrong.",
    "intelligence": "Valkyrie has directly seen this exact behavior before on "
                    "this machine and learned that it's a threat.",
    "behavioral":   "The address this device tried to reach has a computer-"
                    "generated-looking name, a technique malware often uses "
                    "to hide its true destination.",
    "dga":          "The address looks algorithmically generated rather than "
                    "a real, readable web address — a common way malware "
                    "finds its control server.",
    "doh_bypass":   "Something on this device tried to sneak its network "
                    "requests around Valkyrie's filtering — normal software "
                    "doesn't need to do that.",
    "anomaly":      "This device did something it doesn't normally do. That "
                    "alone isn't proof of a problem, but it's unusual enough "
                    "to flag.",
    "tracker":      "This is an advertising or tracking company, not an "
                    "attacker. It's a privacy concern, not a sign this device "
                    "has been broken into.",
    "process":      "Software on this device behaved the way malware often "
                    "does — for example, reaching into another program's "
                    "private memory, or running from a place programs don't "
                    "normally run from.",
    "persistence":  "Something set itself up to start automatically every "
                    "time this device turns on. That's one of the main ways "
                    "attackers stay on a device long after breaking in.",
    "network":      "This device connected directly to an address already "
                    "known to be dangerous, in a way that skipped normal web "
                    "filtering entirely.",
    "tunnel":       "This device made an unusually large number of strange, "
                    "one-off web lookups in a short time — a pattern used to "
                    "sneak data out or commands in without raising a single "
                    "obvious flag.",
    "dyndns":       "This device reached an address on a free hosting service "
                    "that's commonly abused to hide the real destination "
                    "behind a legitimate-looking name.",
    "attack_chain": "Several different warning signs happened together, from "
                    "the same source, in a short window. Any one of them "
                    "alone might be nothing — together, they're a much "
                    "stronger signal.",
    "malware":      "This device's own built-in antivirus positively "
                    "identified this as malicious. This isn't a guess — it's "
                    "a direct verdict on the actual file.",
    "attack_sequence": "This matches a known attack technique step-by-step, "
                    "not just one suspicious action on its own.",
}

# Shipped action -> a plain verb phrase a non-analyst can act on. Every key
# here must stay a real edr/response.py responder, same rule as _RECOMMEND.
_PLAIN_ACTION = {
    "isolate_host":       "disconnect this device from the network",
    "kill_process":       "stop the process involved",
    "block_domain":       "block this destination so nothing on this device can reach it again",
    "remove_persistence": "remove the auto-start entry it created",
    "monitor_only":       "keep watching for now — no action needed yet",
}

# Ordered MOST-specific-first. A detection's real `details["labels"]` (set by
# valkyrie/process_telemetry.py's detector) names the ACTUAL, specific finding
# - "lolbin", "hidden_window", "wrong_parent_system_proc" - where _MEANING's
# per-category text is a lowest-common-denominator paragraph that lists three
# unrelated possibilities ("reading LSASS memory, injecting into another
# process, OR executing from an untrusted location") every single time,
# regardless of which one actually happened. Found in a PHASE 1 audit
# against 500 real incidents: a real "svchost.exe has the wrong parent"
# masquerade detection and a real "PowerShell ran with a hidden window"
# detection were both given the IDENTICAL generic sentence, burying the
# actual, specific, real finding under boilerplate. Priority order matters:
# real data shows several labels routinely co-occurring (lolbin +
# hidden_window + execpolicy_bypass almost always travel together;
# network_anomaly + actor_untrusted + never_resolved always do) - picking
# only the highest-priority match gives ONE precise sentence instead of
# restating the same event three ways.
_LABEL_WHY_PRIORITY = [
    ("cred_browser",           "It copied a saved browser password or cookie file — the way "
                               "attackers steal saved logins without ever seeing a typed password."),
    ("defender_tamper",        "It stopped or deleted a security service on this device — a "
                               "strong sign something is trying to disable protection before "
                               "doing something else."),
    ("impair_defenses",        "It disabled a security-relevant service — attackers do this to "
                               "operate without being watched."),
    ("system_name_lookalike",  "Its name closely imitates a real Windows program (a one-letter-"
                               "off copy) — a common disguise for malware hiding in plain sight."),
    ("wrong_parent_system_proc", "It's a real Windows system process, but it was started by the "
                               "wrong parent process — genuine Windows processes are always "
                               "launched a specific way, and this wasn't it."),
    ("server_spawned_shell",   "A program that normally just serves requests unexpectedly opened "
                               "a command shell — the pattern of a compromised web server."),
    ("payload_from_lowtrust",  "It ran a program from a folder normal software doesn't run from, "
                               "like a temp or downloads folder."),
    ("lolbin_network_fetch",   "It used a legitimate Windows tool to download and run something "
                               "from the internet in one step, without ever saving a normal, "
                               "reviewable file."),
    ("download_cradle",        "It downloaded a program and ran it directly in memory, without "
                               "ever saving it to disk where it could be inspected."),
    ("encoded_powershell",     "It ran a command that was deliberately scrambled (encoded) so its "
                               "real content isn't visible at a glance."),
    ("obfuscated_command",     "It ran a command that was deliberately disguised to hide what it "
                               "actually does."),
    ("base64_decode",          "It decoded a scrambled block of text into a runnable command — a "
                               "common way to sneak a command past simple filters."),
    ("dynamic_exec",           "It downloaded code and ran it immediately, rather than running a "
                               "fixed, reviewable script."),
    ("execpolicy_bypass",      "It turned off a safety check that normally stops unsigned scripts "
                               "from running."),
    ("process_novelty",        "This is the first time this program has ever done this on this "
                               "device."),
    ("hidden_window",          "It ran with its window deliberately hidden — normal, everyday use "
                               "rarely needs to do that."),
    ("lolbin",                 "It used a legitimate, built-in Windows program in a way attackers "
                               "commonly abuse, rather than the way it's normally used."),
    ("network_anomaly",        "It connected to an address that was never looked up through "
                               "normal DNS — the address was already known in advance, which "
                               "legitimate software rarely does."),
    ("actor_untrusted",        "The program making the connection isn't signed or isn't running "
                               "from a trusted location."),
    ("never_resolved",         "The destination was reached directly, skipping the normal address "
                               "lookup step entirely."),
    ("persistence_scheduled_task", "It created a scheduled task, one of the most common ways "
                               "software keeps running in the background after a restart."),
    ("security_service_stop",  "It stopped a security-relevant service."),
]


def _label_based_why(detections: list) -> str:
    """The single most specific, real reason a detection actually fired,
    drawn from the REAL structured labels the engine already attached
    (``details["labels"]``) - never the generic category catch-all. Returns
    "" (never a fabricated reason) when no detection carries a recognized
    label, so the caller falls back to the category-level text.
    """
    all_labels: set = set()
    for d in detections:
        details = d.details if isinstance(d.details, dict) else {}
        labels = details.get("labels")
        if isinstance(labels, list):
            all_labels.update(str(l) for l in labels)
    for label, text in _LABEL_WHY_PRIORITY:
        if label in all_labels:
            return text
    return ""


# Categories that, by their OWN _MEANING/_PLAIN_WHY text, are explicitly not
# themselves evidence of compromise (privacy signal, baseline deviation).
# Confidence cannot exceed "low" on these alone, no matter how it's phrased -
# raising it would misrepresent what the category actually means.
_BENIGN_LEANING_CATEGORIES = frozenset({"tracker", "anomaly"})


def _detection_span_hours(detections: list) -> float:
    """Hours between the earliest and latest PARSEABLE detection timestamp.

    Returns 0.0 when fewer than two timestamps parse - that reads as "no
    evidence of a spread", the same conservative default as an empty
    causality chain: it never MANUFACTURES doubt, it can only surface real
    doubt when the data actually shows one. Tolerates the 'Z' UTC suffix
    Detection.timestamp uses, on every Python version this ships on (only
    3.11+'s fromisoformat accepts 'Z' natively).
    """
    times = []
    for d in detections:
        ts = getattr(d, "timestamp", None)
        if not ts:
            continue
        try:
            times.append(datetime.fromisoformat(str(ts).replace("Z", "+00:00")))
        except (ValueError, TypeError):
            continue
    if len(times) < 2:
        return 0.0
    return (max(times) - min(times)).total_seconds() / 3600.0


# Score -> confidence tier for 'attack_chain' incidents, derived from
# killchain.py's own graded score (tactic diversity scaled by evidence
# strength, lineage verification, and temporal clustering - see that
# module's score_chain() docstring). Recalibrated, not copied, from
# killchain's internal severity buckets (>=0.9 critical/>=0.7 high) because
# investigate.py needs a 4th, more honest floor ("insufficient") that
# killchain's own 3-bucket scale has no use for: a chain built entirely from
# informational, name-linked, loosely-timed signals can score as low as
# ~0.09, and a human-facing report must be allowed to say so rather than
# rounding it up to "low" just because SOME chain fired.
_KILLCHAIN_CONFIDENCE_THRESHOLDS = (
    (0.85, "high"),
    (0.50, "medium"),
    (0.30, "low"),
)


def _killchain_confidence(detections: list) -> Optional[tuple[str, list[str]]]:
    """Confidence tier for an 'attack_chain' incident, read from the REAL
    graded score killchain.py already computed - never re-derived, never
    assumed. Returns None when no detection carries that score (e.g. a
    hand-built or legacy incident predating this), so the caller can fall
    back to the generic evidence-based assessment instead of guessing.

    This is the one rule that makes "never let the human-facing confidence
    layer be more certain than the evidence-generating layer" actually true
    for this category: the tier is a direct, honest function of the same
    score number a technical consumer of the API would see, not a separate,
    more confident-sounding story for humans.
    """
    chain = None
    for d in detections:
        details = d.details if isinstance(d.details, dict) else {}
        c = details.get("chain")
        if isinstance(c, dict) and "score" in c:
            chain = c
            break
    if chain is None:
        return None
    score = chain.get("score")
    if not isinstance(score, (int, float)):
        return None
    tier = "insufficient"
    for floor, name in _KILLCHAIN_CONFIDENCE_THRESHOLDS:
        if score >= floor:
            tier = name
            break
    n_tactics = chain.get("distinct_tactics", "several")
    reason = f"{n_tactics} independent ATT&CK tactics correlated on one actor (score {score:.2f})."
    quality = chain.get("quality") if isinstance(chain.get("quality"), dict) else {}
    if quality.get("evidence", 1.0) < 0.7:
        reason += " Much of the underlying evidence is low-severity or informational."
    if quality.get("lineage", 1.0) < 0.9:
        reason += " Some of the process links are by name only, not directly observed."
    if quality.get("temporal", 1.0) < 0.8:
        reason += " The stages are spread across a large part of the correlation window."
    return tier, [reason]


def _assess_confidence(inc: "Incident", detections: list, cats: list,
                       causality: dict) -> tuple[str, list[str]]:
    """Pure, evidence-grounded confidence tier: "high" | "medium" | "low" |
    "insufficient". Every reason names a real field already on the incident
    or its detections - this never invents corroboration that isn't there,
    and a tier can only be RAISED by real evidence (detection count, severity,
    independently-agreeing detectors), never by a category asserting urgency
    it can't back up on its own.
    """
    n = len(detections)
    if n == 0 and not cats:
        return "insufficient", ["No detections or category are recorded on this incident."]
    if n == 0:
        # A category label exists on the incident, but no individual
        # detection record backs it up - a tag is not evidence. Found in
        # adversarial review: without this check, an incident whose
        # detections were purged (or built directly with only a category
        # set - a real, supported path, e.g. Investigator(edr_store=None))
        # inherited "high" confidence from a scary-sounding category name
        # ("malware") it had no actual record left to verify.
        return "insufficient", [f"The incident is tagged '{'/'.join(sorted(cats))}' but no "
                                f"individual detection record is available to verify it."]

    if "malware" in cats:
        return "high", ["An external antimalware engine directly convicted this "
                        "content (AMSI) — a direct verdict, not a heuristic."]
    if "attack_sequence" in cats:
        # A NAMED, specific attack pattern (behavioral_sequences.py's
        # SequenceEngine) - a different, more precise detector than the
        # generic tactic-diversity count below, and out of scope for the
        # confidence-model fix that follows: it identifies exact tradecraft
        # in order, not "N different tactics happened somewhere in a window".
        reason = (f"{n} independent detections agree on the same actor in a short window."
                  if n >= 2 else "This incident represents multiple correlated tactics from the same actor.")
        return "high", [reason]
    if "attack_chain" in cats:
        chain_conf = _killchain_confidence(detections)
        if chain_conf is not None:
            return chain_conf
        # No killchain quality data recorded on any detection (e.g. a
        # hand-built or legacy incident) - fall through to the same
        # generic, evidence-based assessment below rather than assuming
        # "high" on the category name alone. This IS the fix: "three
        # different ATT&CK tactics happened" used to be treated as
        # unconditional high confidence regardless of how weak or how
        # loosely linked that evidence actually was - a real, code-verified
        # benign developer workflow (IDE terminal -> encoded PowerShell
        # startup -> a build step -> hostname.exe for a build log) crossed
        # the 3-tactic bar and got the same "high confidence, disconnect
        # this device" verdict as a genuine credential-theft chain. The
        # confidence tier for 'attack_chain' now comes from killchain.py's
        # own graded score (see _killchain_confidence) - which factors in
        # evidence strength, lineage verification, and temporal clustering -
        # not from the bare fact that the category is 'attack_chain'.

    only_benign = bool(cats) and all(c in _BENIGN_LEANING_CATEGORIES for c in cats)
    if only_benign:
        return "low", [f"Only {'/'.join(sorted(cats))}-type signal(s) are present — "
                       f"usually not a sign of compromise by themselves."]

    sev = severity_rank(inc.severity)

    # Multiple detections are only genuinely corroborating when they plausibly
    # describe the SAME event: close together in time, and (when causality
    # data exists) the same process lineage. Found in adversarial review:
    # raw detection COUNT alone was being read as corroboration even when the
    # detections were years apart, or from two entirely unrelated process
    # trees merged into one incident - the base incident-grouping this module
    # receives detections from is not guaranteed to enforce either property
    # (see killchain.py's own docstring criticism of "groups by SAME
    # CATEGORY" as too weak). Neither check can RAISE confidence, only hold
    # it back or explain the doubt honestly.
    span = _detection_span_hours(detections)
    distinct_chains = causality.get("chain_count", 1) if causality.get("available") else 1
    coherent = span <= 24.0 and distinct_chains <= 1
    caveat = ""
    if not coherent:
        bits = []
        if span > 24.0:
            bits.append(f"spread across {span:.1f}h")
        if distinct_chains > 1:
            bits.append(f"{distinct_chains} different process lineages")
        caveat = f" ({', '.join(bits)}, so they may not all be one connected event)"

    if n >= 3 and sev >= severity_rank("high"):
        if coherent:
            return "high", [f"{n} separate detections, all high severity or above."]
        return "medium", [f"{n} separate detections, all high severity or above{caveat}."]
    if n >= 2:
        if coherent:
            return "medium", [f"{n} separate detections corroborate each other."]
        return "low", [f"{n} detections are recorded{caveat}."]
    if n == 1 and sev >= severity_rank("high"):
        return "medium", ["A single detection, but of high severity."]
    if n == 1:
        return "low", ["A single detection with no independent corroboration."]
    return "low", ["Only a category-level summary is available, no individual detections."]


def _dedupe_consecutive(names: list) -> list:
    """Collapse immediately-repeated identical names in a chain.

    Real causality data can legitimately show the same binary re-spawning
    itself (a wrapper script re-invoking itself, a relaunch-with-elevation
    pattern) - found live in a PHASE 1 audit: a real chain rendered as
    "...python.exe, which started python.exe, which started python.exe..."
    which reads like a rendering bug even though the underlying data is
    correct. This never changes what happened, only how many times the same
    consecutive name is repeated in the telling of it.
    """
    out: list = []
    for n in names:
        if out and out[-1] == n:
            continue
        out.append(n)
    return out


# Categories whose own detections describe a network/DNS-shaped touchpoint -
# appended as a trailing step so the chain shows where the activity actually
# went, not just which processes ran. Persistence is separate and can follow
# it (matches the worked example: "...python → network connection →
# persistence attempt") because the two are independent outcomes that can
# both be true of the same lineage.
_NET_TOUCHPOINT_CATEGORIES = {"network", "firewall_ip", "dga", "tunnel", "dyndns",
                              "doh_bypass", "intelligence", "behavioral", "tracker"}


def _outcome_clause(cats: list) -> str:
    """A short, factual continuation of the causality sentence for "what
    happened" - describing what the lineage went on to DO, when the
    incident's own categories say so. Never invents intent, success, or
    maliciousness (that framing belongs only in "why it matters"); this only
    ever names a real outcome category already established elsewhere in
    this module, so it can never say more than the evidence supports.
    """
    bits = []
    if any(c in _NET_TOUCHPOINT_CATEGORIES for c in cats):
        bits.append("made an outbound network connection")
    if "persistence" in cats:
        bits.append("an attempt was made to set up automatic startup")
    if not bits:
        return ""
    if len(bits) == 1:
        return f" It then {bits[0]}."
    return f" It then {bits[0]}, and {bits[1]}."


def _how_chain(causality: dict, cats: list) -> str:
    """Compact arrow-chain ("Word → PowerShell → Python → network connection
    → persistence attempt") reusing the exact chain _causality_story already
    derived - no new data, no new query. Trailing steps are only appended
    when the incident's own categories actually say so; a pure process-only
    incident's chain ends on the process, honestly."""
    if not causality.get("available"):
        return ""
    chain = _dedupe_consecutive(_safe_chain(causality.get("chain")))
    if not chain:
        return ""
    parts = list(chain)
    if any(c in _NET_TOUCHPOINT_CATEGORIES for c in cats):
        parts.append("network connection")
    if "persistence" in cats:
        parts.append("persistence attempt")
    return " → ".join(parts)


def _decision_layer(inc: "Incident", detections: list, cats: list, causality: dict,
                    rec_actions: list, what_happened: str) -> dict:
    """The four questions a normal person actually has - what happened, how,
    why it matters, what to do - built only from evidence already computed
    elsewhere in this module (causality, category meanings, the existing
    recommended-action list). No new detection logic; nothing here can make
    an incident look more certain than its own evidence supports, and an
    "insufficient" tier explicitly refuses to guess at an action rather than
    picking one anyway.
    """
    tier, reasons = _assess_confidence(inc, detections, cats, causality)
    how = _how_chain(causality, cats)

    # Prefer the SPECIFIC real finding (details["labels"], e.g. "this system
    # process has the wrong parent" or "PowerShell ran with a hidden window")
    # over the generic category catch-all. Found in a PHASE 1 audit: the
    # category text for "process" lists three unrelated possibilities every
    # time regardless of which one actually happened - real, specific
    # evidence beats a lowest-common-denominator paragraph whenever it exists.
    why = _label_based_why(detections)
    if not why:
        why_bits = [_PLAIN_WHY.get(c, "") for c in cats]
        why = " ".join(b for b in why_bits if b).strip()
    if not why:
        why = ("This doesn't match a specific pattern Valkyrie can explain in "
               "plain terms yet — see the technical detail below.")

    # The STRUCTURED recommended_action must never claim more than the plain
    # text next to it says. Found in adversarial review: at "low" confidence
    # the plain text already says "no immediate action is recommended", but
    # the structured field still named a specific responder action (e.g.
    # isolate_host) - a consumer reading only the structured JSON (the LLM
    # facts payload, or a future API caller) would see a concrete
    # recommendation the prose right next to it was actively disclaiming.
    action = None
    if tier in ("insufficient", "low"):
        if tier == "insufficient":
            action_text = ("There isn't enough evidence in this incident to safely "
                           "recommend an action. Wait for more information, or "
                           "check the technical details below yourself.")
        else:  # low
            action_text = ("This alone isn't strong enough evidence to act on right "
                           "now. No immediate action is recommended, but keep an eye "
                           "out if it happens again.")
    else:
        top = rec_actions[0] if rec_actions else None
        action = top
        plain_verb = _PLAIN_ACTION.get(top["action"], "review this manually") if top else "review this manually"
        if tier == "high":
            action_text = f"If you did not do this yourself, {plain_verb} and investigate what caused it."
        else:  # medium
            action_text = f"This is worth a closer look. If you don't recognize this activity, {plain_verb}."

    return {
        "what_happened":          what_happened,
        "how":                    how,
        "why_it_matters":         why,
        "confidence":             tier,
        "confidence_reasons":     reasons,
        "insufficient_evidence":  tier == "insufficient",
        "recommended_action":     action,
        "recommended_action_plain": action_text,
    }


# The canonical set of categories an incident can carry - the single source of
# truth the explainability gate checks. DNS-path categories are the normalized
# Detection.category values set by the built-in plugins (edr/builtin.py); the
# endpoint categories are telemetry CAT_PROCESS/CAT_PERSISTENCE/CAT_NETWORK
# (telemetry.py) as flowed through EdrEngine. Adding a new category here without
# a _MEANING and _RECOMMEND entry fails tests/test_explainability.py by design.
KNOWN_INCIDENT_CATEGORIES = frozenset({
    "firewall_ip", "intelligence", "behavioral", "dga", "doh_bypass",
    "anomaly", "tracker", "process", "persistence", "network",
    "tunnel", "dyndns", "attack_chain", "attack_sequence", "malware",
})


class Investigator:
    """Produces an investigation report for an incident."""

    def __init__(self, edr_store=None) -> None:
        self._store = edr_store

    # ------------------------------------------------------------------

    def investigate(self, incident: Incident, *, use_ai: bool = False,
                    operator: str = "local") -> dict:
        """Return an investigation dict for ``incident``.

        Always includes the offline heuristic report. When ``use_ai`` is set
        and an AI provider is available, adds an ``ai_narrative`` and marks
        ``analyst`` with the provider name (e.g. ``"anthropic"``, ``"openai"``,
        ``"local"``); otherwise ``analyst = "offline"``.
        """
        detections = []
        if self._store is not None:
            detections = self._store.list_detections(incident_id=incident.id, limit=200)

        report = self._offline_report(incident, detections)
        report["analyst"] = "offline"
        provider = get_provider()
        report["ai_available"] = provider.available()

        if use_ai:
            if not provider.available():
                report["ai_error"] = ("AI investigation requested but no provider is "
                                      "configured (set VALKYRIE_AI_KEY, or "
                                      "VALKYRIE_AI_PROVIDER=local) — showing the "
                                      "offline analysis.")
            else:
                analysis = self._ai_analysis(provider, incident, detections, report)
                if analysis is not None:
                    report["ai_analysis"] = analysis
                    report["ai_narrative"] = analysis.get("assessment", "")
                    report["analyst"] = provider.name
                else:
                    report["ai_error"] = ("AI investigation failed (network or "
                                          "provider) — showing the offline analysis.")
        return report

    # ------------------------------------------------------------------
    # Offline heuristic analyst
    # ------------------------------------------------------------------

    def _offline_report(self, inc: Incident, detections: list) -> dict:
        cats = _distinct([d.category for d in detections]) or ([inc.category] if inc.category else [])
        techniques = _distinct([d.technique for d in detections if d.technique])
        entities = _distinct([d.entity for d in detections if d.entity]) or (
            [inc.entity] if inc.entity else [])

        # attack_chain incidents leave inc.process_name blank on purpose (see
        # engine.py's _correlate_chain: two different real chains can share
        # the same display name, so correlation no longer keys on it) - fall
        # back to the killchain-computed origin actor for DISPLAY only. Every
        # detection on an attack_chain incident carries the same chain
        # summary, so the first one found is enough.
        display_process = inc.process_name
        if not display_process:
            for d in detections:
                details = d.details if isinstance(d.details, dict) else {}
                actors = (details.get("chain") or {}).get("actors")
                if isinstance(actors, list) and actors:
                    display_process = actors[0]
                    break

        meaning = " ".join(_MEANING.get(c, "") for c in cats).strip() or \
            "Correlated security detections were grouped into this incident."

        # Severity rationale.
        worst = inc.severity
        why_sev = {
            "critical": "Contains critical-severity detections — treat as an active compromise.",
            "high":     "High-severity detections present — likely malicious, act promptly.",
            "medium":   "Medium-severity — suspicious behaviour worth investigating.",
            "low":      "Low-severity — routine blocks (e.g. trackers); informational.",
            "info":     "Informational only.",
        }.get(worst, "")

        # Recommended actions, de-duplicated in priority order across categories.
        rec_actions: list[dict] = []
        seen = set()
        for c in cats:
            for act in _RECOMMEND.get(c, []):
                if act in seen:
                    continue
                seen.add(act)
                target = ""
                rationale = ""
                if act == "block_domain":
                    target = entities[0] if entities else ""
                    rationale = "Stop this endpoint from reaching the malicious domain."
                elif act == "kill_process":
                    target = str(display_process and _first_pid(detections) or "")
                    rationale = f"Terminate the offending process ({display_process or 'unknown'})."
                elif act == "isolate_host":
                    rationale = ("Network-contain this endpoint until triaged — this "
                                 "category indicates possible active C2.")
                rec_actions.append({"action": act, "target": target,
                                    "rationale": rationale})

        # Timeline digest - most recent first, capped.
        timeline = [
            {"timestamp": d.timestamp, "severity": d.severity,
             "title": d.title, "entity": d.entity, "source": d.source}
            for d in detections[:20]
        ]

        # entities[0] is very often just inc.process_name again (the "primary
        # indicator" of a process-centric incident IS the process) - named
        # once, not twice ("involving FileCoAuth.exe; primary indicator:
        # FileCoAuth.exe" was a real, verbatim duplicate found in a PHASE 1
        # audit against live data).
        indicator = entities[0] if entities and entities[0] != display_process else ""

        summary = (
            f"{inc.title}. {why_sev} {meaning} "
            f"{len(detections)} detection(s) observed"
            + (f" involving {display_process}" if display_process else "")
            + (f"; primary indicator: {indicator}." if indicator else ".")
        ).strip()

        # Causality: reads what edr/engine.py's _enrich_causality() already
        # attached to each detection (det.details["causality"]) - this makes
        # no graph query of its own, so a detection with no attributed process
        # (e.g. a bare network-IP block) simply contributes nothing rather
        # than being guessed at. See _causality_story()'s own docstring for
        # the honesty rule this must never violate.
        causality = _causality_story(detections)

        # "story" (-> decision.what_happened, the primary human-facing text)
        # is a PURELY FACTUAL narrative - never the interpretive/technical
        # _MEANING paragraph, which belongs only in "why it matters" and
        # "technical detail". Found in a PHASE 1 audit: every single real
        # incident sampled repeated the identical _MEANING sentence in BOTH
        # "what happened" and "technical detail" - an analyst would never
        # say the same paragraph twice in one report.
        if causality["available"] and causality.get("sentence"):
            story = (causality["sentence"] + _outcome_clause(cats)).strip()
        else:
            # No causality data: the incident's own title is real, specific
            # evidence (built by the detector, e.g. "'svchost.exe' has parent
            # 'system idle process'... — masquerade or injection") - use it
            # as the factual lead instead of a generic template, but without
            # the technical meaning paragraph glued on.
            n = len(detections)
            count_bit = f"{n} detection" + ("" if n == 1 else "s")
            readable_indicator = indicator if _is_readable_indicator(indicator) else ""
            tail = f" ({count_bit}" + (f", primary indicator: {readable_indicator}" if readable_indicator else "") + ")."
            lead = (inc.title.rstrip(". ") if inc.title else "Valkyrie recorded a security signal")
            story = lead + "." + tail

        # The four-question human decision layer: what happened / how / why it
        # matters / what to do. Built entirely from the evidence already
        # assembled above (cats, causality, rec_actions) - see _decision_layer's
        # own docstring for the honesty rule it must never violate.
        decision = _decision_layer(inc, detections, cats, causality, rec_actions, story)

        return {
            "incident_id":  inc.id,
            "severity":     worst,
            "status":       inc.status,
            "summary":      summary,
            "story":        story,
            "meaning":      meaning,
            "categories":   cats,
            "techniques":   techniques,
            "entities":     entities[:20],
            "process":      display_process,
            "detection_count": len(detections),
            "timeline":     timeline,
            "recommended_actions": rec_actions,
            "causality":    causality,
            "decision":     decision,
        }

    # ------------------------------------------------------------------
    # LLM-assisted narrative (opt-in, vendor-neutral)
    # ------------------------------------------------------------------

    def _ai_analysis(self, provider: AIProvider, inc: Incident, detections: list,
                     offline: dict) -> Optional[dict]:
        """The LLM as an *explainable assistant*, never a detector.

        The model receives only the compact facts the offline analyst already
        derived (no raw event dump, no browsing history) and must return a
        structured verdict: an assessment, a confidence level, and ONE
        recommended action drawn from the response actions Valkyrie actually
        ships - with the evidence lines (quoted from the provided facts) that
        justify it. Structured output makes every conclusion auditable; any
        failure returns None and the offline analysis stands alone. The
        ``provider`` is any vendor-neutral backend (see ai_provider.py).
        """
        # Compact, structured facts for the model - no raw event dump. The
        # causality entry reuses what _offline_report() already computed
        # (offline["causality"]) rather than re-deriving it - one honesty
        # rule, one place it can be gotten wrong.
        cz = offline.get("causality") or {"available": False}
        causality_facts = {"available": cz.get("available", False)}
        if cz.get("available"):
            causality_facts.update({
                "process_started_by": cz.get("cgo"),
                "process_chain": cz.get("chain"),
                "chain_observed_or_inferred": "inferred" if cz.get("inferred") else "observed",
                "supporting_detections": cz.get("supporting_detections"),
                "related_process_lineages": cz.get("chain_count"),
            })
        facts = {
            "title": inc.title,
            "severity": inc.severity,
            "process": offline.get("process") or inc.process_name,
            "categories": offline["categories"],
            "techniques": offline["techniques"],
            "indicators": offline["entities"][:15],
            "detections": [
                {"title": d.title, "severity": d.severity, "entity": d.entity,
                 "reason": d.details.get("reason", "")}
                for d in detections[:25]
            ],
            "causality": causality_facts,
            # The offline analyst's own evidence-grounded confidence tier -
            # reused verbatim from _offline_report(), not recomputed, so the
            # model is anchored to the same evidence rather than free to
            # invent its own read of how strong the evidence is.
            "offline_confidence": {
                "tier": offline["decision"]["confidence"],
                "reasons": offline["decision"]["confidence_reasons"],
            },
            "available_actions": ["block_domain", "kill_process",
                                  "isolate_host", "monitor_only"],
        }
        schema = {
            "type": "object",
            "properties": {
                "assessment": {
                    "type": "string",
                    "description": "3-6 sentence analyst assessment of what "
                                   "most likely happened and why it matters."},
                "confidence": {"type": "string",
                               "enum": ["low", "medium", "high"]},
                "likely_technique": {
                    "type": "string",
                    "description": "The single most relevant MITRE technique "
                                   "from the provided facts, or empty."},
                "recommended_action": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string",
                                   "enum": ["block_domain", "kill_process",
                                            "isolate_host", "monitor_only"]},
                        "target": {"type": "string"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["action", "target", "rationale"],
                    "additionalProperties": False,
                },
                "evidence": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Facts from the input that support the "
                                   "assessment — quote, never invent."},
            },
            "required": ["assessment", "confidence", "likely_technique",
                         "recommended_action", "evidence"],
            "additionalProperties": False,
        }
        system = (
            "You are a senior SOC analyst assisting an endpoint security "
            "product called Valkyrie. You explain and prioritize — you are "
            "not a detector, and detections stand on their own without you. "
            "Analyze ONLY the structured facts provided. Never invent "
            "indicators, hosts, or techniques that are not in the facts; "
            "every evidence entry must be traceable to the input. When the "
            "facts include a process chain marked 'inferred', you MUST "
            "preserve that distinction in your assessment - never state an "
            "inferred process relationship as a directly observed fact. "
            "offline_confidence is the deterministic analyst's own evidence-"
            "grounded confidence tier - treat it as a CEILING, not a floor: "
            "you may report LOWER confidence if you see a specific reason to, "
            "but never report a HIGHER confidence than the evidence in these "
            "facts actually supports. If the evidence is thin, say so plainly "
            "rather than picking a confident-sounding action anyway. Choose the "
            "recommended action from available_actions only, preferring the "
            "least destructive action that contains the threat. Respond with "
            "ONLY a JSON object conforming to the given schema — no prose."
        )
        import json as _json
        user = (
            "Investigate this incident and reply with ONLY a JSON object that "
            "conforms to this JSON Schema:\n" + _json.dumps(schema) +
            "\n\nIncident facts:\n" + _json.dumps(facts, indent=2)
        )
        # Delegate the transport to the vendor-neutral provider.
        out = provider.analyze(system, user, schema)
        if not isinstance(out, dict):
            return None
        # Defense in depth: even a schema-conforming reply must not smuggle an
        # action outside the shipped set (provider-independent guard).
        if out.get("recommended_action", {}).get("action") not in (
                "block_domain", "kill_process", "isolate_host", "monitor_only"):
            return None
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ai_available() -> bool:
    """True only if a configured AI provider can actually be called."""
    return get_provider().available()


def _distinct(items: list) -> list:
    out: list = []
    for x in items:
        if x and x not in out:
            out.append(x)
    return out


def _safe_chain(raw) -> list:
    """Defensively extract a list of names from a causality stamp's ``chain``
    field. ``raw`` is trusted to be a list in the happy path (edr/engine.py
    always produces one), but this module also has to survive a corrupted or
    hand-built causality dict without crashing - found live in adversarial
    review: ``(raw or [])`` looks like a safe default, but a TRUTHY
    non-iterable (e.g. ``chain: 12345`` from malformed data) sails straight
    past the ``or []`` and into ``for n in 12345``, which raises. Only a real
    list is ever iterated; anything else degrades to "no chain" rather than
    crashing the whole investigation.
    """
    if not isinstance(raw, list):
        return []
    return [n for n in raw if n]


def _chain_sentence(c: dict) -> str:
    """One sentence naming a process chain, CGO first - honest about inference.

    ``c`` is one detection's ``details["causality"]`` stamp (see
    edr/engine.py's ``_enrich_causality``): ``chain`` is CGO-first,
    target-process-last. Returns "" for a chain too short to narrate (a lone
    process has no ancestry worth a sentence) rather than a degenerate one.
    """
    chain = _dedupe_consecutive(_safe_chain(c.get("chain")))
    if len(chain) < 2:
        return ""
    pieces = [chain[0]] + [f"started {name}, which" for name in chain[1:]]
    sentence = " ".join(pieces)
    if sentence.endswith(", which"):
        sentence = sentence[: -len(", which")]
    if c.get("inferred"):
        sentence += " — part of this chain is inferred, not directly observed"
    return sentence + "."


def _causality_story(detections: list) -> dict:
    """Derive a structured, honest process-ancestry summary from the
    causality data ALREADY attached to each detection by edr/engine.py's
    ``_enrich_causality()`` (``det.details["causality"]``).

    This reads what is already there; it makes no query of its own against
    the causality graph. A detection with no attributed process (no pid, or
    the graph never resolved one) simply contributes nothing here - it is
    never guessed at. When multiple detections in the incident share the
    IDENTICAL chain, only one contributes to the story (the "does not repeat
    itself" requirement); the deepest distinct chain is the representative
    one, since it is the most descriptive.

    Returns ``{"available": False}`` when no detection carries a causality
    stamp with real ancestry (chain length >= 2) - callers must fall back to
    their existing behavior in that case, never fabricate a chain.
    """
    chains: list[dict] = []
    seen_paths: set[str] = set()
    path_counts: dict[str, int] = {}
    for d in detections:
        details = d.details if isinstance(d.details, dict) else {}
        c = details.get("causality")
        if not isinstance(c, dict):
            continue
        path = c.get("path")
        chain = _safe_chain(c.get("chain"))
        if not path or len(chain) < 2:
            continue  # no real ancestry to narrate
        path_counts[path] = path_counts.get(path, 0) + 1
        if path in seen_paths:
            continue
        seen_paths.add(path)
        chains.append(c)

    if not chains:
        return {"available": False}

    # Most descriptive (deepest) chain represents the story; ties broken by
    # first-seen order, so the result is deterministic given the same input.
    primary = max(chains, key=lambda c: c.get("depth") or 0)
    distinct_cgos = _distinct([c.get("cgo") for c in chains])

    sentence = _chain_sentence(primary)
    if sentence and len(chains) > 1:
        if len(distinct_cgos) == 1:
            sentence += (f" {len(chains)} related process lineages in this "
                        f"incident share the same origin, {primary.get('cgo')}.")
        elif len(chains) - 1 >= 5:
            # A handful of extra lineages is a normal correlated incident; a
            # large number (found live: one real incident merged 19) is a
            # sign the underlying grouping bundled loosely-related events
            # together rather than describing one connected story - said
            # plainly here rather than only in the confidence caveat, so a
            # reader of "what happened" alone isn't misled into thinking
            # this one chain is the whole incident.
            sentence += (f" This incident actually groups {len(chains)} separate, unrelated "
                        f"process lineages together, not one connected chain - the story above "
                        f"describes only the most detailed one, {primary.get('cgo')}.")
        else:
            sentence += (f" This incident also involves {len(chains) - 1} "
                        f"other process lineage(s) with a different origin.")

    return {
        "available": bool(sentence),
        "cgo": primary.get("cgo"),
        "cgo_pid": primary.get("cgo_pid"),
        "chain": primary.get("chain") or [],
        "path": primary.get("path"),
        "depth": primary.get("depth"),
        "inferred": bool(primary.get("inferred")),
        "chain_count": len(chains),
        "supporting_detections": path_counts.get(primary.get("path"), 0),
        "sentence": sentence,
    }


def _is_readable_indicator(value: str) -> bool:
    """Is this indicator string short enough and plain enough to show a
    normal reader in the primary narrative? Found in a PHASE 1 audit: a real
    persistence incident's "primary indicator" was a raw scheduled-task path
    containing a Windows SID and a GUID (`scheduled_task::SoftLanding\\S-1-5-
    21-.../{bd8a9e72-...}`) - technically correct, unreadable to anyone. Such
    values still appear in `entities`/`summary` for an analyst; they are only
    withheld from the plain "what happened" sentence.
    """
    if not value or len(value) > 60:
        return False
    if "S-1-5-" in value or "{" in value:
        return False
    return True


def _first_pid(detections: list) -> int:
    for d in detections:
        if d.process_pid:
            return d.process_pid
    return 0
