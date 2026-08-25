#!/usr/bin/env python3
"""The shipped imported ruleset (valkyrie/defaults/imported_rules.json).

Detection content from elastic/protections-artifacts (Elastic 2.0) and SigmaHQ
(DRL 1.1), each rule having survived the import funnel. This suite guards the
three ways shipping borrowed content goes wrong:

  [ALIVE]   an imported rule that can never match inflates the coverage number
            and detects nothing. Fake parity is the failure this project
            refuses to ship, so every shipped rule must be able to fire.
  [ATTRIB]  both licences require attribution wherever matches are shown. A rule
            that loses its provenance is a licence violation AND an unauditable
            detection.
  [SEPARATE] native and borrowed coverage must stay countable apart, or "how
            many techniques do we detect" becomes a number nobody can attribute.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.behavioral_rules import (  # noqa: E402
    RULES, IMPORTED_RULES, ALL_RULES, IMPORTED_RULES_PATH,
    load_imported_rules, match_process,
)


def main() -> int:
    c = Checks("Imported vendor/community rules — shipped, alive, attributed",
               expect_min=18)

    # ================================================================ [1]
    print("\n[1] the ruleset ships and loads")
    c.check("imported rules loaded", len(IMPORTED_RULES) > 50)
    c.check("native corpus is unchanged by the import", len(RULES) == 168)
    c.check("ALL_RULES is native + imported",
            len(ALL_RULES) == len(RULES) + len(IMPORTED_RULES))

    # ============================================== [SEPARATE] KEYSTONE
    print("\n[SEPARATE] KEYSTONE: borrowed coverage stays countable apart "
          "from our own")
    native_ids = {r.id for r in RULES}
    imported_ids = {r.id for r in IMPORTED_RULES}
    c.check("no id collisions between native and imported",
            not (native_ids & imported_ids))
    c.check("every imported rule is identifiable by id prefix",
            all(r.id.startswith(("elastic-", "sigma-")) for r in IMPORTED_RULES))
    c.check("imported rules carry a distinguishing label",
            all(r.label in ("elastic_import", "sigma_import")
                for r in IMPORTED_RULES))

    # ================================================== [ALIVE] KEYSTONE
    print("\n[ALIVE] KEYSTONE: a rule that cannot fire is worse than one we "
          "refused — it is coverage on paper and nothing in fact")
    dead = [r.id for r in IMPORTED_RULES
            if not (r.images or r.parents or r.cmd_all or r.cmd_any
                    or r.cmd_any2 or r.cmd_any3 or r.path_any)]
    c.check("no imported rule lacks a positive condition", not dead)
    wildcarded = [r.id for r in IMPORTED_RULES
                  if any("*" in n or "?" in n
                         for n in tuple(r.images) + tuple(r.parents))]
    c.check("no imported rule keys on a wildcard basename it can never match",
            not wildcarded)
    stray = [r.id for r in IMPORTED_RULES
             if any(n.startswith("-") or "." not in n
                    for n in tuple(r.images) + tuple(r.parents))]
    c.check("no argument leaked into an image/parent list (parser sanity)",
            not stray)

    # ================================================= [ATTRIB] KEYSTONE
    print("\n[ATTRIB] KEYSTONE: attribution rides on every rule, because both "
          "licences require it where matches are DISPLAYED")
    c.check("every imported rule names its source in `reason`",
            all(("SigmaHQ" in r.reason or "elastic" in r.reason.lower())
                for r in IMPORTED_RULES))
    c.check("every imported rule names its licence",
            all(("DRL-1.1" in r.reason or "Elastic-2.0" in r.reason)
                for r in IMPORTED_RULES))
    payload = json.loads(IMPORTED_RULES_PATH.read_text(encoding="utf-8"))
    prov = payload.get("_provenance", {})
    c.check("the shipped file carries a provenance block", bool(prov.get("sources")))
    c.check("both corpora are credited with licence and URL",
            all(s.get("license") and s.get("url")
                for s in prov["sources"].values()))
    c.check("the file states attribution must not be stripped",
            "attribution" in (prov.get("notice") or "").lower())

    # ================================================================ [2]
    print("\n[2] imported rules actually FIRE through the engine's own path")
    fired = {h.rule_id for h in match_process(
        "certoc.exe", "cmd.exe", r"certoc.exe -LoadDLL C:\Users\Public\a.dll", "")}
    c.check("an Elastic rule fires end-to-end",
            any(r.startswith("elastic-") for r in fired))
    hit_any = False
    for r in IMPORTED_RULES:
        if r.images and r.cmd_all:
            probe = f"{r.images[0]} " + " ".join(r.cmd_all)
            if any(h.rule_id == r.id for h in
                   match_process(r.images[0], "cmd.exe", probe, "")):
                hit_any = True
                break
    c.check("a Sigma/Elastic rule reconstructed from its own terms fires", hit_any)

    # ================================================================ [3]
    print("\n[3] technique coverage is real and mapped")
    mapped = [r for r in IMPORTED_RULES if r.technique and r.technique != "unmapped"]
    c.check("most imported rules carry an ATT&CK technique",
            len(mapped) >= int(len(IMPORTED_RULES) * 0.8))
    c.check("imported content spans many techniques",
            len({r.technique for r in mapped}) >= 20)

    # ================================================================ [4]
    print("\n[4] a missing or damaged corpus degrades, never crashes")
    c.check("missing file -> empty tuple, no exception",
            load_imported_rules(Path("no-such-imported-rules.json")) == ())

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
