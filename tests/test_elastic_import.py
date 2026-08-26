#!/usr/bin/env python3
"""Elastic endpoint rule import (valkyrie/edr/elastic_import.py).

Elastic publishes the behavioural detection content that ships in their real
endpoint agent, under a licence that permits derivative works. This suite is
built around an ACTUAL published rule, copied verbatim from
`elastic/protections-artifacts`, because an importer proven only against
hand-written fixtures is proven against the author's own assumptions.

Three keystones:

  [NEVER-BROADEN] a rule carrying exclusions Valkyrie cannot enforce is REFUSED.
        Importing its positive half would ship a rule with MORE false positives
        than Elastic themselves accept — on a real person's machine.
  [HARVEST] the same refused rule still yields its false-positive knowledge.
        That knowledge protects rules Valkyrie wrote itself, and it is the half
        a solo developer cannot generate at any effort level.
  [LINEAGE] `descendant of [...]` converts intact, because Valkyrie has a
        causality graph. Sigma cannot express it at all.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks  # noqa: E402
from valkyrie.edr.content_license import License, ShipMode  # noqa: E402
from valkyrie.edr.adaptive import BENIGN_CORPUS  # noqa: E402
from valkyrie.edr.elastic_import import (  # noqa: E402
    ElasticVerdict, convert, harvest_exclusions, import_rules, summarise,
    corpus_from_facts, load_harvested_corpus, full_benign_corpus,
)


# --------------------------------------------------------------------------
# A REAL rule: elastic/protections-artifacts, behavior/rules/windows/
# command_and_control_ingress_tool_transfer_via_curl.toml (Elastic License v2)
# --------------------------------------------------------------------------
REAL_CURL_RULE = r'''
[rule]
description = "Identifies downloads of remote content using Windows CURL."
id = "336ada1c-69f8-46e8-bdd2-790c85429696"
license = "Elastic License v2"
name = "Ingress Tool Transfer via CURL"
os_list = ["windows"]
version = "1.0.34"

query = """
process where event.action == "start" and
 process.executable : ("?:\\Windows\\System32\\curl.exe", "?:\\Windows\\SysWOW64\\curl.exe") and
 (
  (process.args_count == 2 and process.command_line : "*http*" and process.parent.name : "cmd.exe") or
  (process.args : ("-o", "--output") and
   (
     (process.parent.name : "cmd.exe" and process.parent.command_line : ("*curl*")) or
     descendant of [process where process.name : ("winword.exe", "excel.exe")] or
     process.parent.executable : ("?:\\Users\\Public\\*")
   ))
 ) and
 not (process.parent.name : "cmd.exe" and process.parent.args : ("*.bat*", "curl -L -o \\\\*")) and
 not process.command_line : ("*http://127.0.0.1:*", "*http://localhost:*") and
 not process.args : ("https://mirror.init7.net/ctan/systems*", "texlive/curl",
                     "http://control.firstvoucher.com/api/build/*zip",
                     "https://blackhole.blob.core.windows.net/*",
                     "https://dl.google.com/*") and
 not user.id : "S-1-5-18" and
 not (process.parent.command_line like~ "*VoicemodInstaller*")
"""

[[threat]]
framework = "MITRE ATT&CK"
[[threat.technique]]
id = "T1105"
name = "Ingress Tool Transfer"
'''


def _rule(query: str, *, license: str = "Elastic License v2",
          name: str = "Test Rule", os_list=("windows",)) -> dict:
    return {"rule": {"name": name, "id": "test-1", "license": license,
                     "os_list": list(os_list), "version": "1.0.0",
                     "query": query},
            "threat": [{"technique": [{"id": "T1059"}]}]}


def main() -> int:
    c = Checks("Elastic endpoint rule import — detections, and the exclusions",
               expect_min=26)

    real = tomllib.loads(REAL_CURL_RULE)

    # ============================================ [NEVER-BROADEN] KEYSTONE
    print("\n[NEVER-BROADEN] KEYSTONE: a real rule whose exclusions we cannot "
          "enforce is REFUSED, not half-imported")
    rule, verdict, reasons, prov = convert(real)
    c.check("the real Elastic rule parses without raising", verdict is not None)
    c.check("it is NOT imported", rule is None)
    c.check("refused as unparseable/unsupported, not silently trimmed",
            verdict in (ElasticVerdict.SKIP_UNPARSEABLE,
                        ElasticVerdict.SKIP_TELEMETRY))
    c.check("the reason states dropping a clause would BROADEN the rule",
            any("broader" in r.lower() or "more false positives" in r.lower()
                for r in reasons))

    # ===================================================== [HARVEST] KEYSTONE
    print("\n[HARVEST] KEYSTONE: the REFUSED rule still gives up its "
          "real-world false-positive knowledge")
    facts = harvest_exclusions(real)
    markers = {f.marker for f in facts}
    c.check("facts were harvested from a rule we refused", len(facts) >= 5)
    c.check("a LaTeX mirror is known-benign",
            any("mirror.init7.net" in m for m in markers))
    c.check("Google's own downloader is known-benign",
            any("dl.google.com" in m for m in markers))
    c.check("a voice-changer installer is known-benign",
            any("voicemodinstaller" in m for m in markers))
    c.check("loopback URLs are known-benign",
            any("127.0.0.1" in m for m in markers))
    c.check("nested exclusions inside or-groups are found too "
            "(harvest is greedier than import, on purpose)",
            any(".bat" in m for m in markers))
    c.check("every fact carries the rule it came from (auditable)",
            all(f.source_rule == "Ingress Tool Transfer via CURL" for f in facts))
    entries = corpus_from_facts(facts)
    c.check("facts render as (image, parent, cmdline) corpus triples",
            entries and all(len(e) == 3 for e in entries))

    # ================================================================ [0]
    print("\n[0] licence is gate ZERO — checked before any parsing work")
    _, v, reasons, prov = convert(_rule('process where process.name : "a.exe"',
                                        license="CC BY-NC 4.0"))
    c.check("a non-commercial rule is refused", v == ElasticVerdict.SKIP_LICENSE)
    c.check("the licence is recorded per rule",
            prov.license == License.CC_BY_NC_4_0)
    _, v, _, _ = convert(_rule('process where process.name : "a.exe"', license=""))
    c.check("an UNLICENSED rule is refused (fail closed)",
            v == ElasticVerdict.SKIP_LICENSE)
    _, v, _, _ = convert(_rule('process where process.name : "a.exe"'),
                         mode=ShipMode.HOSTED_SERVICE)
    c.check("Elastic content is refused for a HOSTED SERVICE build",
            v == ElasticVerdict.SKIP_LICENSE)

    # ================================================================ [1]
    print("\n[1] a clean exclusion-free rule imports with BOTH anchors intact")
    rule, v, _, prov = convert(_rule(
        'process where event.action == "start" and '
        'process.name : "rundll32.exe" and process.parent.name : "winword.exe"'))
    c.check("imported", v == ElasticVerdict.IMPORTED and rule is not None)
    c.check("image anchor kept", rule.images == ("rundll32.exe",))
    c.check("parent anchor kept (no conjunct dropped)",
            "winword.exe" in rule.parents)
    c.check("ATT&CK technique carried across", rule.technique == "T1059")
    c.check("attribution rides on the rule",
            "Elastic" in rule.reason and "Elastic-2.0" in rule.reason)

    # ===================================================== [LINEAGE] KEYSTONE
    print("\n[LINEAGE] KEYSTONE: `descendant of` converts INTACT — Sigma "
          "cannot express this at all")
    rule, v, _, _ = convert(_rule(
        'process where process.name : "powershell.exe" and '
        'descendant of [process where process.name : ("winword.exe", "excel.exe")]'))
    c.check("a lineage rule imports", v == ElasticVerdict.IMPORTED)
    c.check("both document ancestors survive",
            "winword.exe" in rule.parents and "excel.exe" in rule.parents)

    # ================================================================ [2]
    print("\n[2] telemetry Valkyrie does not collect is refused BY NAME")
    _, v, reasons, _ = convert(_rule(
        'process where process.name : "a.exe" and '
        'process.code_signature.subject_name : "Contoso*"'))
    c.check("code-signature rule refused", v == ElasticVerdict.SKIP_TELEMETRY)
    c.check("the unsupported field is named, not hand-waved",
            any("code_signature" in r for r in reasons))
    _, v, _, _ = convert(_rule('file where file.name : "x.dll"'))
    c.check("a non-process event source is refused", v == ElasticVerdict.SKIP_TELEMETRY)

    # ================================================================ [3]
    print("\n[3] a command-line-only rule has no anchor and is too broad")
    _, v, _, _ = convert(_rule(
        'process where process.command_line : "*whoami*"'))
    c.check("no process/parent/ancestor anchor -> refused",
            v == ElasticVerdict.SKIP_NO_ANCHOR)

    # ================================================================ [4]
    print("\n[4] the false-positive gate still applies to vendor content")
    res = import_rules([_rule(
        'process where process.name : "git.exe" and '
        'process.command_line : "*clone*"', name="Suspicious Git")])
    c.check("a rule that breaks a real developer command is rejected",
            res[0].verdict == ElasticVerdict.REJECT_FP)
    c.check("the offending benign command is named", len(res[0].fired_on) >= 1)

    # ================================================================ [5]
    print("\n[5] the corpus summary reports the honest funnel")
    res = import_rules([real,
                        _rule('process where process.name : "rundll32.exe" and '
                              'process.parent.name : "winword.exe"'),
                        _rule('process where process.name : "a.exe"',
                              license="CC BY-NC 4.0")])
    s = summarise(res)
    c.check("counts everything considered", s["total"] == 3)
    c.check("counts only what truly imported", s["imported"] == 1)
    c.check("REPORTS the benign knowledge gained from REFUSED rules",
            s["benign_facts_from_refused_rules"] >= 5)

    # ================================================================ [7]
    print("\n[7] the harvested corpus is SHIPPED and WIRED — the FP gate is "
          "measured against real fleet knowledge, not 18 hand-written commands")
    harvested = load_harvested_corpus()
    full = full_benign_corpus()
    c.check("the harvested corpus ships with Valkyrie", len(harvested) > 400)
    c.check("every shipped entry names its process (valid FP evidence)",
            all(e[0] and e[2] for e in harvested))
    c.check("the full corpus is hand-written PLUS harvested",
            len(full) > len(BENIGN_CORPUS) + 400)
    c.check("the hand-written corpus is still included, not replaced",
            all(e in full for e in BENIGN_CORPUS))
    c.check("a missing corpus file degrades to 'we know less', never raises",
            load_harvested_corpus(Path("no-such-file-anywhere.json")) == [])

    # ================================================================ [6]
    print("\n[6] a malformed corpus never crashes the importer")
    try:
        res = import_rules([{}, None, {"rule": {"query": "!!!"}}, real])
        c.check("bad entries skipped, processing continues", len(res) >= 2)
    except Exception as exc:   # noqa: BLE001
        c.fail("bad entries skipped, processing continues", repr(exc))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
