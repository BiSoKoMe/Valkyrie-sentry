"""Detection-content supply chain — provenance and per-rule licensing.

WHY THIS EXISTS
---------------
Valkyrie imports detection content from outside: SigmaHQ, Elastic's published
endpoint rules, community YARA. That is the correct engineering decision - no
security team on earth writes its corpus from scratch, and hand-writing rule
#169 while a decade of vetted public content sits there is working hard instead
of working smart.

But imported content arrives with strings attached, and **the strings are not
uniform across a repository**. That is the trap this module exists to close.

The concrete example that motivated it: Florian Roth's `signature-base` relicensed
from CC-BY-NC to DRL 1.1 in 2021, but individual rule files in that repo still
carry the old CC-BY-NC header. CC-BY-NC forbids commercial use. A repo-level
license check says "DRL, fine, import everything" and quietly ships
non-commercial content inside a product somebody paid for. Nobody notices until
it is a legal problem rather than an engineering one.

So licensing here is a property of **each rule**, carried with it forever, and
checked against **what Valkyrie is actually doing with it**.

FAIL CLOSED
-----------
The single most important line in this file is that ``UNKNOWN`` is not
shippable. Absence of a license is not permission - it is the default state of
"all rights reserved". An importer that treats unlabelled content as free is the
same bug as an allowlist that defaults to allow.

DISTRIBUTION MODE IS PART OF THE QUESTION
-----------------------------------------
"May we use this rule?" has no answer without "to do what?". The same rule can
be perfectly legal in a desktop agent and a violation in a hosted service:

  * **CC-BY-NC** is fine for personal use, forbidden the moment you sell it.
  * **Elastic License 2.0** grants use, copy, distribute, and derivative works -
    genuinely generous, and it covers shipping a desktop product. Its one real
    limit is that you may not offer the software to third parties *as a hosted
    or managed service*. Valkyrie is an on-device agent, so today this content
    is clean. If Valkyrie ever grows a cloud tier, ``ShipMode.HOSTED_SERVICE``
    makes the gate withdraw that content automatically instead of relying on
    somebody remembering this paragraph two years from now.

That is why ``may_ship`` takes a mode. Encoding the restriction in the type
system means the future change is caught by a gate, not by memory.

ATTRIBUTION IS A RUNTIME REQUIREMENT, NOT A FILE HEADER
-------------------------------------------------------
DRL 1.1 is specific in a way that is easy to get wrong: attribution must appear
in *the views that show matches*. Crediting the author in a source comment does
not satisfy it. So every provenance record can render an ``attribution()``
string, and any UI that displays a detection from imported content is expected
to display it. It is a product requirement, not paperwork.

Pure: no I/O, no globals. Classification is a function of text, and the ship
decision is a function of (license, mode). Fully testable offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional


class License(str, Enum):
    """Licenses we can recognise. Anything unrecognised becomes UNKNOWN, which
    is deliberately not shippable."""

    DRL_1_1 = "DRL-1.1"                 # SigmaHQ; commercial OK, attribution required
    ELASTIC_V2 = "Elastic-2.0"          # use/copy/distribute/derive; NOT as a hosted service
    MIT = "MIT"
    APACHE_2 = "Apache-2.0"
    BSD_3 = "BSD-3-Clause"
    CC_BY_4_0 = "CC-BY-4.0"
    CC_BY_SA_4_0 = "CC-BY-SA-4.0"       # share-alike: derivative content must carry it too
    CC_BY_NC_4_0 = "CC-BY-NC-4.0"       # NON-COMMERCIAL - the one that bites
    GPL_3 = "GPL-3.0"
    AGPL_3 = "AGPL-3.0"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class ShipMode(str, Enum):
    """What Valkyrie is doing with the content. The licence question is
    meaningless without this."""

    PERSONAL_USE = "personal_use"            # the developer's own machine
    COMMERCIAL_PRODUCT = "commercial_product"  # a desktop agent people pay for
    HOSTED_SERVICE = "hosted_service"        # a cloud tier serving third parties


# --- what each licence forbids -------------------------------------------
# Encoded as capability sets rather than booleans so the reasons stay specific
# and a future mode does not silently inherit a permissive default.

_NON_COMMERCIAL = frozenset({License.CC_BY_NC_4_0})

# Strong copyleft. For detection *content* the reciprocal obligation is
# arguable, but "arguable" is not a basis on which to ship somebody else's work
# inside a closed product, so these are refused and the reason says why.
_COPYLEFT = frozenset({License.GPL_3, License.AGPL_3, License.CC_BY_SA_4_0})

# Grants derivative works and redistribution, but explicitly not as a managed
# service providing substantially the same functionality.
_NO_HOSTED_SERVICE = frozenset({License.ELASTIC_V2})

# Requires the author be credited wherever matches are displayed.
_ATTRIBUTION_REQUIRED = frozenset({
    License.DRL_1_1, License.ELASTIC_V2, License.CC_BY_4_0,
    License.CC_BY_SA_4_0, License.CC_BY_NC_4_0, License.APACHE_2,
    License.MIT, License.BSD_3,
})

_NEVER_SHIPPABLE = frozenset({License.UNKNOWN, License.PROPRIETARY})


# --- recognition ----------------------------------------------------------
# Ordered most-specific first: "CC-BY-NC" must be tested before "CC-BY", and
# "AGPL" before "GPL", or a permissive prefix swallows a restrictive licence.
_PATTERNS: tuple = (
    (License.CC_BY_NC_4_0, re.compile(
        r"(creativecommons\.org/licenses/by-nc|\bCC[\s_-]?BY[\s_-]?NC\b|"
        r"attribution[\s-]*non[\s-]?commercial)", re.I)),
    (License.CC_BY_SA_4_0, re.compile(
        r"(creativecommons\.org/licenses/by-sa|\bCC[\s_-]?BY[\s_-]?SA\b)", re.I)),
    (License.CC_BY_4_0, re.compile(
        r"(creativecommons\.org/licenses/by/|\bCC[\s_-]?BY[\s_-]?4\.0\b)", re.I)),
    (License.AGPL_3, re.compile(r"\bAGPL\b|affero", re.I)),
    (License.GPL_3, re.compile(r"\bGPL[\s_-]?(?:v?3)?\b|general public license", re.I)),
    (License.DRL_1_1, re.compile(
        r"detection[\s_-]?rule[\s_-]?licen[cs]e|\bDRL[\s_-]?1\.1\b|\bDRL\b", re.I)),
    (License.ELASTIC_V2, re.compile(
        r"elastic licen[cs]e\s*(?:v?2(?:\.0)?)?|\bElastic-2\.0\b", re.I)),
    (License.APACHE_2, re.compile(r"apache licen[cs]e|\bApache-2\.0\b", re.I)),
    (License.BSD_3, re.compile(r"\bBSD[\s_-]?3|3-clause bsd", re.I)),
    (License.MIT, re.compile(r"\bMIT licen[cs]e\b|\bMIT\b(?!\s*[A-Za-z])", re.I)),
    (License.PROPRIETARY, re.compile(
        r"all rights reserved|proprietary|confidential", re.I)),
)


def classify(text: Optional[str]) -> License:
    """Identify the licence a piece of content declares about ITSELF.

    Takes the rule's own licence field, header comment, or bundled licence text
    - never the repository default, because the whole point is that those
    disagree. Empty or unrecognised input returns UNKNOWN, which the ship gate
    refuses.
    """
    if not text or not str(text).strip():
        return License.UNKNOWN
    blob = str(text)
    for lic, pattern in _PATTERNS:
        if pattern.search(blob):
            return lic
    return License.UNKNOWN


@dataclass(frozen=True)
class Provenance:
    """Where a rule came from. Travels with the rule for its whole life.

    This is what makes an imported detection auditable: an analyst looking at an
    alert can see which corpus it came from, who wrote it, and under what terms
    - rather than a rule appearing in the engine with no explanation.
    """

    source: str                  # e.g. "SigmaHQ", "elastic/protections-artifacts"
    rule_id: str = ""            # the upstream id, so it can be traced back
    author: str = ""
    license: License = License.UNKNOWN
    url: str = ""
    version: str = ""            # upstream rule version, if it has one

    def attribution(self) -> str:
        """The credit line that must be shown WHEREVER MATCHES ARE DISPLAYED.

        DRL 1.1 requires attribution in views showing matches, and Elastic 2.0
        forbids obscuring notices - a source-code comment satisfies neither.
        """
        who = self.author.strip() or self.source
        bits = [f"{who} ({self.source}"]
        if self.rule_id:
            bits.append(f", id={self.rule_id}")
        bits.append(f", {self.license.value})")
        return "".join(bits)

    def requires_attribution(self) -> bool:
        return self.license in _ATTRIBUTION_REQUIRED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["license"] = self.license.value
        return d


@dataclass(frozen=True)
class ShipDecision:
    allowed: bool
    reason: str
    attribution: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def may_ship(prov: Provenance,
             mode: ShipMode = ShipMode.COMMERCIAL_PRODUCT) -> ShipDecision:
    """May this content ship, given what Valkyrie is doing with it?

    Fails closed. Every refusal states the specific clause, so a rejection is
    actionable ("relicense it / ask the author / write our own") rather than an
    opaque no.
    """
    lic = prov.license

    if lic in _NEVER_SHIPPABLE:
        if lic == License.UNKNOWN:
            return ShipDecision(
                False,
                "no licence declared; absence of a licence is not permission "
                "(unlicensed work is all-rights-reserved by default), so this "
                "is refused rather than assumed free")
        return ShipDecision(
            False, "content is proprietary / all-rights-reserved; it cannot be "
                   "redistributed regardless of how it was obtained")

    if lic in _COPYLEFT:
        return ShipDecision(
            False,
            f"{lic.value} is a reciprocal/share-alike licence; shipping it inside "
            f"a closed product would impose obligations on Valkyrie's own content "
            f"that have not been accepted - refused as unresolved, not as illegal")

    if lic in _NON_COMMERCIAL and mode is not ShipMode.PERSONAL_USE:
        return ShipDecision(
            False,
            f"{lic.value} forbids commercial use, and the current mode is "
            f"{mode.value}; this is exactly the mixed-header case that a "
            f"repository-level licence check would have missed")

    if lic in _NO_HOSTED_SERVICE and mode is ShipMode.HOSTED_SERVICE:
        return ShipDecision(
            False,
            f"{lic.value} grants derivative works and redistribution, but not "
            f"providing the software to third parties as a hosted or managed "
            f"service; permitted in a desktop agent, refused in a cloud tier")

    attribution = prov.attribution() if prov.requires_attribution() else ""
    note = ("; attribution must be displayed wherever its matches are shown"
            if attribution else "")
    return ShipDecision(True, f"{lic.value} permits {mode.value}{note}", attribution)


def audit(provenances: list,
          mode: ShipMode = ShipMode.COMMERCIAL_PRODUCT) -> dict:
    """Summarise a whole imported corpus: what may ship, what may not, and the
    exact reasons. Intended to be reportable - "we imported N, shipped M,
    refused K for these clauses" is an answer; "we imported N" is not."""
    allowed: list = []
    refused: list = []
    by_license: dict = {}
    for prov in provenances:
        by_license[prov.license.value] = by_license.get(prov.license.value, 0) + 1
        decision = may_ship(prov, mode)
        (allowed if decision.allowed else refused).append((prov, decision))
    return {
        "mode": mode.value,
        "total": len(provenances),
        "shippable": len(allowed),
        "refused": len(refused),
        "by_license": by_license,
        "refusals": [{"source": p.source, "rule_id": p.rule_id,
                      "license": p.license.value, "reason": d.reason}
                     for p, d in refused],
        "attributions": sorted({d.attribution for _, d in allowed if d.attribution}),
    }
