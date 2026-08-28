"""Privacy/security consequence scoring over an existing causality subgraph.

This is intentionally a narrow experiment, not a generic "privacy is malware"
rule.  It may only originate a signal when a mature local baseline shows a
*rare descendant egress* in a complete browser/document lineage that already
contains an attributable, masked Nyx leak observation.  Raw request content is
neither accepted nor returned by this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from .causal_detect import CausalBaseline, MIN_OBSERVATIONS, MIN_SESSIONS

_INTERACTIVE_OWNERS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "winword.exe", "excel.exe",
    "powerpnt.exe", "outlook.exe", "acrord32.exe", "thunderbird.exe",
})
_EGRESS_KINDS = frozenset({"dns", "network", "connection"})


@dataclass(frozen=True)
class ConsequenceFinding:
    fires: bool = False
    destination: str = ""
    network_destination: str = ""
    privacy_categories: tuple[str, ...] = ()
    reason: str = ""
    suppressed_by: str = ""


def score_privacy_consequence(sub: dict, baseline: CausalBaseline) -> ConsequenceFinding:
    """Return a DNS-enforceable *future egress* finding, or an honest refusal.

    The originating privacy request has already happened; callers must never
    describe this as prevention of that request.  The destination is suitable
    only for a later DNS decision, and only when baseline maturity guards have
    made "first seen" meaningful.
    """
    if not sub or not sub.get("found"):
        return ConsequenceFinding(suppressed_by="no_subgraph")
    if not baseline.mature:
        return ConsequenceFinding(
            suppressed_by="baseline_immature",
            reason=(f"baseline has {baseline.observations}/{MIN_OBSERVATIONS} observations "
                    f"across {baseline.sessions}/{MIN_SESSIONS} sessions"),
        )
    if sub.get("truncated") or sub.get("inferred_nodes") or sub.get("evicted"):
        return ConsequenceFinding(suppressed_by="incomplete_provenance")

    cgo = sub.get("cgo") or {}
    owner = str(cgo.get("name") or "").lower()
    if owner not in _INTERACTIVE_OWNERS:
        return ConsequenceFinding(suppressed_by="non_interactive_owner")

    artifacts = [a for a in sub.get("artifacts") or [] if isinstance(a, dict)]
    leaks = [a for a in artifacts if str(a.get("kind") or "").lower() == "nyx_leak"]
    if not leaks:
        return ConsequenceFinding(suppressed_by="no_privacy_artifact")

    # Nyx attribution is deliberately metadata-only. Refuse malformed or
    # content-bearing inputs rather than allowing a future caller to smuggle a
    # body/query/value into incident details through this path.
    categories, destinations = set(), set()
    forbidden = {"body", "raw", "raw_content", "content", "query", "value"}
    for leak in leaks:
        data = leak.get("data") or {}
        if not isinstance(data, dict) or any(k.lower() in forbidden for k in data):
            return ConsequenceFinding(suppressed_by="privacy_boundary_violation")
        category = str(data.get("privacy_category") or data.get("category") or "").lower()
        destination = str(data.get("destination_host") or "").lower()
        if category:
            categories.add(category)
        if destination:
            destinations.add(destination)
    if not categories or len(destinations) != 1:
        return ConsequenceFinding(suppressed_by="ambiguous_privacy_destination")

    owner_key = str(cgo.get("key") or "")
    egress = []
    for artifact in artifacts:
        if str(artifact.get("kind") or "").lower() not in _EGRESS_KINDS:
            continue
        # A consequence must be caused by a descendant, not merely the browser
        # itself issuing the same request Nyx observed.
        if str(artifact.get("process") or "").lower() == owner:
            continue
        data = artifact.get("data") or {}
        subject = str(data.get("subject") or "").lower() if isinstance(data, dict) else ""
        process = str(artifact.get("process") or "").lower()
        kind = str(artifact.get("kind") or "").lower()
        if subject and baseline.artifact_rarity(process, kind) >= 0.90:
            egress.append((subject, process, kind))
    if not egress:
        return ConsequenceFinding(suppressed_by="no_rare_descendant_egress")

    destination = next(iter(destinations))
    network_destination = egress[-1][0]
    return ConsequenceFinding(
        fires=True, destination=destination, network_destination=network_destination,
        privacy_categories=tuple(sorted(categories)),
        reason=("A browser/document lineage produced a masked privacy observation "
                f"to {destination} and a rare descendant {egress[-1][2]} consequence "
                f"to {network_destination}. The original request was observed, not prevented."),
    )
