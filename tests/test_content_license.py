#!/usr/bin/env python3
"""Detection-content supply chain (valkyrie/edr/content_license.py).

Valkyrie imports detection content from outside. The risk is not that the
importer converts a rule wrongly - that shows up in testing. The risk is that it
ships somebody's non-commercial or unlicensed work inside a product, which shows
up as a legal problem years later with no engineering signal in between.

The two keystones:

  [NC]   the mixed-header case that a repo-level check misses: a repository that
         says DRL, containing a rule that says CC-BY-NC. The RULE wins.
  [FAIL-CLOSED] unlicensed content is refused. Absence of a licence is not
         permission - it is all-rights-reserved by default.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.edr.content_license import (  # noqa: E402
    License, ShipMode, Provenance, classify, may_ship, audit,
)


def main() -> int:
    c = Checks("Detection-content supply chain — licence before import", expect_min=24)

    # ================================================================ [1]
    print("\n[1] licences are recognised from the content's OWN declaration")
    c.check("Sigma's DRL", classify("Detection Rule License 1.1") == License.DRL_1_1)
    c.check("Elastic's per-rule field",
            classify('license = "Elastic License v2"') == License.ELASTIC_V2)
    c.check("MIT", classify("MIT License") == License.MIT)
    c.check("Apache", classify("Apache License, Version 2.0") == License.APACHE_2)

    # ================================================================ [NC] KEYSTONE
    print("\n[NC] KEYSTONE: the mixed-header case — the RULE's licence wins, "
          "not the repository's")
    # signature-base relicensed to DRL in 2021, but files still carry CC-BY-NC.
    repo_says = classify("Detection Rule License 1.1")
    rule_says = classify(
        "/* Florian Roth - https://creativecommons.org/licenses/by-nc/4.0/ */")
    c.check("the repo reads as DRL (shippable)", repo_says == License.DRL_1_1)
    c.check("the individual rule reads as CC-BY-NC", rule_says == License.CC_BY_NC_4_0)
    nc = Provenance(source="Neo23x0/signature-base", rule_id="apt_x",
                    author="Florian Roth", license=rule_says)
    decision = may_ship(nc, ShipMode.COMMERCIAL_PRODUCT)
    c.check("shipping it commercially is REFUSED", not decision.allowed)
    c.check("the refusal names the non-commercial clause",
            "commercial" in decision.reason.lower())
    c.check("the same rule IS allowed for personal use",
            may_ship(nc, ShipMode.PERSONAL_USE).allowed)

    # ============================================== [FAIL-CLOSED] KEYSTONE
    print("\n[FAIL-CLOSED] KEYSTONE: no licence means NO, never 'probably fine'")
    c.check("empty text classifies as UNKNOWN", classify("") == License.UNKNOWN)
    c.check("None classifies as UNKNOWN", classify(None) == License.UNKNOWN)
    unk = Provenance(source="random-github-repo", license=License.UNKNOWN)
    d = may_ship(unk)
    c.check("UNKNOWN is refused in every mode",
            not d.allowed
            and not may_ship(unk, ShipMode.PERSONAL_USE).allowed)
    c.check("the reason explains all-rights-reserved is the DEFAULT",
            "not permission" in d.reason)

    # ================================================================ [2]
    print("\n[2] Elastic 2.0: shippable in a desktop agent, refused in a cloud tier")
    el = Provenance(source="elastic/protections-artifacts",
                    rule_id="336ada1c", author="Elastic",
                    license=License.ELASTIC_V2)
    c.check("desktop product: ALLOWED",
            may_ship(el, ShipMode.COMMERCIAL_PRODUCT).allowed)
    hosted = may_ship(el, ShipMode.HOSTED_SERVICE)
    c.check("hosted service: REFUSED", not hosted.allowed)
    c.check("the refusal names the managed-service clause",
            "managed service" in hosted.reason or "hosted" in hosted.reason)

    # ================================================================ [3]
    print("\n[3] copyleft is refused as UNRESOLVED, and says so honestly")
    gpl = Provenance(source="somewhere", license=License.GPL_3)
    d = may_ship(gpl)
    c.check("GPL refused", not d.allowed)
    c.check("refused as unresolved, not asserted illegal", "unresolved" in d.reason)
    c.check("AGPL is not mistaken for GPL",
            classify("GNU Affero General Public License") == License.AGPL_3)

    # ================================================================ [4]
    print("\n[4] ordering: a permissive prefix must not swallow a restrictive licence")
    c.check("CC-BY-NC is not read as CC-BY",
            classify("CC BY-NC 4.0") == License.CC_BY_NC_4_0)
    c.check("CC-BY-SA is not read as CC-BY",
            classify("CC BY-SA 4.0") == License.CC_BY_SA_4_0)
    c.check("plain CC-BY still resolves",
            classify("https://creativecommons.org/licenses/by/4.0/") == License.CC_BY_4_0)

    # ================================================================ [5]
    print("\n[5] attribution is renderable for the views that show matches")
    sig = Provenance(source="SigmaHQ", rule_id="abc-123",
                     author="Nasreddine Bencherchali", license=License.DRL_1_1)
    d = may_ship(sig)
    c.check("DRL content ships", d.allowed)
    c.check("an attribution string is produced", bool(d.attribution))
    c.check("it names the author AND the upstream id",
            "Nasreddine" in d.attribution and "abc-123" in d.attribution)
    c.check("the permission states attribution must be DISPLAYED",
            "displayed" in d.reason)

    # ================================================================ [6]
    print("\n[6] a whole corpus audits into a reportable answer")
    corpus = [sig, el, nc, unk,
              Provenance(source="Atomic Red Team", license=License.MIT)]
    rep = audit(corpus, ShipMode.COMMERCIAL_PRODUCT)
    c.check("counts the whole corpus", rep["total"] == 5)
    c.check("only licence-clean content is shippable", rep["shippable"] == 3)
    c.check("every refusal carries a specific reason",
            len(rep["refusals"]) == 2
            and all(r["reason"] for r in rep["refusals"]))
    c.check("attribution lines are collected for the UI",
            len(rep["attributions"]) >= 2)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
