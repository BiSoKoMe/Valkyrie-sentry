"""AI-assisted investigation.

Turns a raw incident (a pile of correlated detections) into an analyst-style
writeup: what happened, why it matters, and what to do about it.

Two modes:

  * **Offline heuristic (default, always available).** A deterministic,
    fully-local analyst built from the incident's own detections — severity
    rationale, observed MITRE techniques, affected process/entities, a timeline
    digest, and concrete recommended response actions. No network, no key.

  * **Claude-assisted (opt-in, off by default).** If — and only if — the
    operator explicitly enables it AND an API key is present, the incident is
    summarised by Claude for a richer narrative. This SENDS incident details
    (including domains) to a third party, so it is deliberately gated: it
    respects the same "opt-in, off by default, clearly disclosed" rule the
    platform roadmap sets for any telemetry that leaves the machine. Any error
    (no key, no SDK, network blocked) silently falls back to the offline
    analyst — the investigation always returns something useful.
"""

from __future__ import annotations

import os
from typing import Optional

from .schema import Incident, severity_rank


# The model is a product configuration, overridable by the operator. Defaults to
# the latest widely-available Claude model per the Anthropic SDK guidance.
_DEFAULT_MODEL = os.environ.get("VALKYRIE_AI_MODEL", "claude-opus-4-8")

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
}

# Category -> which response actions the analyst recommends, in priority order.
_RECOMMEND = {
    "firewall_ip":  ["isolate_host", "kill_process", "block_domain"],
    "intelligence": ["block_domain", "kill_process"],
    "behavioral":   ["block_domain"],
    "dga":          ["block_domain", "kill_process"],
    "doh_bypass":   ["kill_process", "block_domain"],
    "anomaly":      ["block_domain"],
    "tracker":      ["block_domain"],
}


class Investigator:
    """Produces an investigation report for an incident."""

    def __init__(self, edr_store=None) -> None:
        self._store = edr_store

    # ------------------------------------------------------------------

    def investigate(self, incident: Incident, *, use_ai: bool = False,
                    operator: str = "local") -> dict:
        """Return an investigation dict for ``incident``.

        Always includes the offline heuristic report. When ``use_ai`` is set
        and a key/SDK are available, adds an ``ai_narrative`` and marks
        ``analyst = "claude"``; otherwise ``analyst = "offline"``.
        """
        detections = []
        if self._store is not None:
            detections = self._store.list_detections(incident_id=incident.id, limit=200)

        report = self._offline_report(incident, detections)
        report["analyst"] = "offline"
        report["ai_available"] = _ai_available()

        if use_ai:
            if not _ai_available():
                report["ai_error"] = ("AI investigation requested but no API key is "
                                      "configured (set ANTHROPIC_API_KEY) — showing the "
                                      "offline analysis.")
            else:
                analysis = self._ai_analysis(incident, detections, report)
                if analysis is not None:
                    report["ai_analysis"] = analysis
                    report["ai_narrative"] = analysis.get("assessment", "")
                    report["analyst"] = "claude"
                else:
                    report["ai_error"] = ("AI investigation failed (network or SDK) — "
                                          "showing the offline analysis.")
        return report

    # ------------------------------------------------------------------
    # Offline heuristic analyst
    # ------------------------------------------------------------------

    def _offline_report(self, inc: Incident, detections: list) -> dict:
        cats = _distinct([d.category for d in detections]) or ([inc.category] if inc.category else [])
        techniques = _distinct([d.technique for d in detections if d.technique])
        entities = _distinct([d.entity for d in detections if d.entity]) or (
            [inc.entity] if inc.entity else [])

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
                    target = str(inc.process_name and _first_pid(detections) or "")
                    rationale = f"Terminate the offending process ({inc.process_name or 'unknown'})."
                elif act == "isolate_host":
                    rationale = ("Network-contain this endpoint until triaged — this "
                                 "category indicates possible active C2.")
                rec_actions.append({"action": act, "target": target,
                                    "rationale": rationale})

        # Timeline digest — most recent first, capped.
        timeline = [
            {"timestamp": d.timestamp, "severity": d.severity,
             "title": d.title, "entity": d.entity, "source": d.source}
            for d in detections[:20]
        ]

        summary = (
            f"{inc.title}. {why_sev} {meaning} "
            f"{len(detections)} detection(s) observed"
            + (f" involving {inc.process_name}" if inc.process_name else "")
            + (f"; primary indicator: {entities[0]}." if entities else ".")
        ).strip()

        return {
            "incident_id":  inc.id,
            "severity":     worst,
            "status":       inc.status,
            "summary":      summary,
            "meaning":      meaning,
            "categories":   cats,
            "techniques":   techniques,
            "entities":     entities[:20],
            "process":      inc.process_name,
            "detection_count": len(detections),
            "timeline":     timeline,
            "recommended_actions": rec_actions,
        }

    # ------------------------------------------------------------------
    # Claude-assisted narrative (opt-in)
    # ------------------------------------------------------------------

    def _ai_analysis(self, inc: Incident, detections: list,
                     offline: dict) -> Optional[dict]:
        """Claude as an *explainable assistant*, never a detector.

        The model receives only the compact facts the offline analyst already
        derived (no raw event dump, no browsing history) and must return a
        structured verdict: an assessment, a confidence level, and ONE
        recommended action drawn from the response actions Valkyrie actually
        ships — with the evidence lines (quoted from the provided facts) that
        justify it. Structured output makes every conclusion auditable; any
        failure returns None and the offline analysis stands alone.
        """
        try:
            import anthropic
        except ImportError:
            return None
        try:
            client = anthropic.Anthropic()
        except Exception:
            return None

        # Compact, structured facts for the model — no raw event dump.
        facts = {
            "title": inc.title,
            "severity": inc.severity,
            "process": inc.process_name,
            "categories": offline["categories"],
            "techniques": offline["techniques"],
            "indicators": offline["entities"][:15],
            "detections": [
                {"title": d.title, "severity": d.severity, "entity": d.entity,
                 "reason": d.details.get("reason", "")}
                for d in detections[:25]
            ],
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
            "every evidence entry must be traceable to the input. Choose the "
            "recommended action from available_actions only, preferring the "
            "least destructive action that contains the threat."
        )
        import json as _json
        try:
            resp = client.messages.create(
                model=_DEFAULT_MODEL,
                max_tokens=2048,
                thinking={"type": "adaptive"},
                system=system,
                output_config={"format": {"type": "json_schema",
                                          "schema": schema}},
                messages=[{"role": "user",
                           "content": "Investigate this incident:\n" +
                                      _json.dumps(facts, indent=2)}],
            )
        except Exception:
            return None
        try:
            text = next(b.text for b in resp.content
                        if getattr(b, "type", "") == "text")
            out = _json.loads(text)
        except Exception:
            return None
        # Defense in depth: even a schema-conforming reply must not smuggle an
        # action outside the shipped set.
        if out.get("recommended_action", {}).get("action") not in (
                "block_domain", "kill_process", "isolate_host", "monitor_only"):
            return None
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ai_available() -> bool:
    """True only if a key is present AND the SDK importable — never assumes."""
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("VALKYRIE_AI_KEY")):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def _distinct(items: list) -> list:
    out: list = []
    for x in items:
        if x and x not in out:
            out.append(x)
    return out


def _first_pid(detections: list) -> int:
    for d in detections:
        if d.process_pid:
            return d.process_pid
    return 0
