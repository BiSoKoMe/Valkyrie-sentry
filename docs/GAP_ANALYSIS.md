# Valkyrie - Capability Gap Analysis (honest)

Reviewed 2026-07-18. Compares Valkyrie's **actual implemented** capability against
CrowdStrike, Microsoft Defender, SentinelOne, Palo Alto, Cisco, Google, Apple,
Bitdefender, Sophos, Malwarebytes, Proton, Cloudflare. No feature is claimed that
does not exist in code.

## Where Valkyrie is genuinely competitive (local, no external scale needed)
| Capability | Status | Notes |
|---|---|---|
| DNS filtering / sinkhole | Strong local | Real resolver + sinkhole; competitive with Pi-hole/NextDNS. Gap: blocklist breadth. |
| Telemetry reduction | Strong local | Registry/service edits, reversible (cf. O&O ShutUp10). |
| Windows privacy hardening | Strong local | MAC randomization, DoH-bypass detection, telemetry killer. |
| Local-first privacy | Strong | Everything on-box, no cloud account. Genuine differentiator. |
| Application firewall | Moderate | `netsh advfirewall` outbound rules; works, not kernel-level. |

## Where Valkyrie is materially weaker (ranked)
Ranked by (security impact x user value x **honest local feasibility**). Items
needing global scale (signature clouds, ML from millions of endpoints) are marked
"needs infra" - per project policy we do **not** fake those.

| Rank | Gap | Security | User value | Local feasibility | Verdict |
|---|---|---|---|---|---|
| **1** | **Ransomware protection** | **Critical** | **Very high** | **High** (behavioral canary + entropy + I/O attribution is a real local technique) | **✅ SHIPPED** (Ransomware Shield) |
| 2 | Threat intelligence (local IOC feeds) | High | Med | High (pull real public feeds: URLhaus, Feodo, ThreatFox) | **✅ SHIPPED** 2026-07-18 (ADR 0015, `valkyrie/threat_intel.py`) |
| 3 | Behavioral detection depth | High | Med | Med (ETW process/file/registry sensors) | Iterative |
| 4 | SIEM integration (CEF/syslog export) | Med | Med (enterprise) | High | Cheap win later |
| 5 | Digital forensics / triage collection | Med | Med | High | Later |
| 6 | Malware detection (files) | Critical | High | **Needs infra** | **✅ PARTIAL** 2026-07-28 (ADR 0035, `valkyrie/amsi.py`): the OS AMSI provider is integrated for content verdicts. Still no Valkyrie signature engine - we borrow a verdict, we do not have parity |
| 7 | Exploit / memory-attack detection | Critical | High | Low-Med (ETW/AMSI, no kernel driver) | Partial only; honest boundary |
| 8 | Kernel protection (minifilter/ELAM) | Critical | High | **Needs signed driver** | Document as extension point |
| 9 | Cloud analytics / global ML | High | Med | **Needs infra** | Architecture only, privacy-preserving |

## Selected highest-value improvement: **Ransomware Shield**
Rationale: it is the most destructive endpoint threat, Valkyrie currently has
**zero** coverage, every named competitor ships it, and - critically - a strong
version is achievable **locally and honestly**:

- **Canary tripwires**: decoy files in real users' document folders; ransomware
  that enumerates and encrypts files hits them, giving a near-zero-false-positive
  high-confidence signal. (Used by CryptoDrop, parts of Malwarebytes/Acronis.)
- **Entropy confirmation**: encrypted output is ~7.99 bits/byte - corroborates.
- **Behavioral rate**: mass file modification bursts as a secondary signal.
- **Response**: attribute the writer via per-process disk-I/O, then **suspend**
  (reversible, halts encryption in place) and raise a CRITICAL incident.

### Honest capability boundary (what commercial adds that we do NOT claim)
- **Kernel minifilter (real-time write blocking + exact PID attribution).** Our
  attribution is a documented I/O heuristic; a signed filesystem minifilter is
  required for deterministic pre-write blocking. -> Documented extension point in
  `docs/RANSOMWARE_SHIELD.md`.
- **VSS/rollback of already-encrypted files.** We halt in place; we do not yet
  restore. Extension point noted.
- **Global ransomware-family intelligence.** Out of scope without infra.

Result: the strongest *local* ransomware defense we can honestly ship, with clean
seams for the kernel/rollback/intel upgrades that require more than one endpoint.

## Cycle 2026-07-18: Threat-intel IOC feeds - SHIPPED
Rank-2 gap closed per plan: `valkyrie/threat_intel.py` pulls Feodo Tracker,
URLhaus, and ThreatFox (SSLBL evaluated and rejected - deprecated 2025-01-03),
caches on disk, matches locally at ~1 µs, and enforces at three seams: DNS
decision (before the learned known-good fast path), resolved-answer C2-IP
sinkholing, and network-collector -> EDR incidents. See ADR 0015 and
docs/THREAT_INTEL.md. Live verification: 2,394 IOCs from 3/3 feeds in 1.8 s.

**Next candidates (re-ranked)**: (a) SIEM/CEF export - cheap, enterprise
value; (b) behavioral detection depth via more ETW channels; (c) digital
forensics triage collection. URL-path IOC matching unlocks when the TLS
inspector exposes URLs to the intel engine.

## Cycle 2026-07-19: SIEM export - SHIPPED
Rank-4 gap closed (ADR 0016, `valkyrie/siem.py`): CEF + JSON Lines over
udp/tcp/tls/file, queue-buffered + reconnecting (peer-close MSG_PEEK
detection), incidents always / DNS blocks behind a second domain-carrying
opt-in, `/api/siem/status` observability. Tests 22/22 incl. live loopback
transports and EDR end-to-end. Platform vision codified honestly in
docs/ARCHITECTURE.md (shipped / buildable / infra-boundary tiers).

**Next candidates**: (a) digital-forensics triage bundle per incident;
(b) SOAR-style playbooks over existing response actions; (c) more ETW
channels; (d) compliance report generator over incident history.

## Cycles 2026-07-19 (continued): four enterprise pillars - SHIPPED
- **Forensics triage** (ADR 0017): per-incident evidence zip (incident+
  timeline, ±30min events, process tree, connections, ASEP, host) with
  SHA256 manifest + tamper-detecting verify_bundle; ~200ms live.
- **SOAR playbooks** (ADR 0018): YAML incident->response automation through
  the audited ResponseManager; dry-run default, enforce opt-in, cooldowns.
- **Compliance evidence reports** (ADR 0019): live-computed MTTR/coverage/
  audit-trail JSON+Markdown; evidence-not-certification honesty built in.
- **AI assistant** (ADR 0020): structured evidence-grounded incident
  analysis, enum-bounded recommendations, explain-only - never a detector.

**Remaining top candidates**: (a) more ETW channels / kernel-ETW consumer
seam; (b) vulnerability visibility (installed software vs local CVE feed);
(c) browser protection via TLS-inspector + URLhaus full URLs; (d) update
*apply* path (staged, rollback-capable); (e) app-side UI for incidents/
playbooks/forensics (electron/ - the product surface).

## Cycle 2026-07-19: detection-efficacy program + DGA C2 detection - SHIPPED
Measurement-first cycles closing the "unmeasured detector" gap (Validation
Philosophy: *if a detector cannot be measured, it is incomplete*):
- **Efficacy harness** (ADR 0022): `tests/efficacy/` drives the real
  classifiers against a MITRE-tagged corpus + benign controls; scores
  recall/FPR as a regression gate. First run found + fixed a real WScript
  `//b` silent-exec gap.
- **ETW/sensor coverage + CI gate** (ADR 0023): extended to `classify_sysmon`
  (T1055/T1003.001/T1055.012/T1574/T1547.001), `classify_wmi` (T1546.003),
  `classify_process` (T1204.002/T1218), `classify_connection` (T1071); gate
  wired into CI. Measured coverage ~doubled; surfaced the DGA blind spot.
- **DGA C2 detection** (ADR 0024): closed the measured blind spot with a
  corroborated, precision-first classifier (`valkyrie/dga.py`) - registrable-
  label scoring + length/entropy/bigram-implausibility corroboration, wired
  into `SiteScanner` (T1568.002). Baseline **0% -> 76% recall at 100%
  precision, 0% FPR** on a hard CDN/brand/foreign benign set. Short-label DGA
  remains the honest "needs infra" boundary - not faked.
- **Host-safety fix**: `test_firewall.py` section 9 (live `netsh` rule
  install) is now opt-in behind `VALKYRIE_TEST_LIVE_FIREWALL=1` and always
  tears down in a `finally`, so a routine `run_tests.py` can never strand the
  host offline. (Reliability Philosophy: never harm the machine it runs on.)

## Cycle 2026-07-19: efficacy coverage for the ETW/sensor classifiers - SHIPPED
ADR 0023. The efficacy harness (ADR 0022) measured 7 classifiers; four shipped
families carried real ATT&CK techniques with **zero measurement**. Extended the
corpus (15->27 malicious, 16->25 benign) to drive `classify_sysmon`
(T1055 / T1055.012 / T1003.001 / T1574 / T1547.001), `classify_wmi` (T1546.003),
`classify_process` (T1204.002 / T1218), and `classify_connection` (T1071, via the
real `ThreatIntelManager`) - each malicious technique paired with a benign
control. Recall/FPR held at 100% / 0%; measured technique coverage ~doubled
across 6 tactics. Gate wired into CI (`.github/workflows/tests.yml`). Surfaced a
**measured DGA blind spot** (high-entropy 2LD C2 domains are allowed by design -
entropy alone can't clear the block threshold without false-positiving on CDN
hostnames of identical entropy); recorded honestly rather than gamed into the
corpus, queued as the next dedicated cycle (corroborated DGA detector).

**Next candidates (re-ranked)**: (a) corroborated DGA detector
(entropy + n-gram improbability + no known-good parent SLD, FP-validated);
(b) VM lab (Atomic Red Team + lab beacon) for the sensor-capture dimension the
in-repo harness structurally cannot measure; (c) vulnerability visibility
(installed software vs local CVE feed); (d) browser protection via
TLS-inspector + URLhaus full URLs.

## Cycle 2026-07-28: AMSI content scanning - SHIPPED (rank-6 gap, partially)
ADR 0035, `valkyrie/amsi.py`. Every endpoint verdict Valkyrie could previously
produce was a **heuristic**; it had zero content conviction. This integrates the
OS **Antimalware Scan Interface** - the documented path this document has
recommended since the first review - so script blocks and files get a real
verdict from the installed antimalware provider. Wired into the PowerShell
script-block sensor (which already holds the *deobfuscated* text), producing a
new `malware` incident category that correlates with everything else on the same
lineage. Strictly additive: an absent, stopped, silent, or raising scanner leaves
the heuristic output unchanged (pinned by four tests). ~1-6 ms per scan.

**Live testing corrected a wrong assumption, which is why it was run.** The first
implementation inferred "no provider" from a non-conviction on Microsoft's AMSI
test marker. On the dev host that inference was false: `AMServiceEnabled: False`
(Defender stands down because Avast + McAfee are installed) and neither
third-party provider recognises the marker *or* EICAR through AMSI - yet both
provider DLLs are demonstrably resident and answering. Provider presence is now
read from `HKLM\SOFTWARE\Microsoft\AMSI\Providers` plus `GetModuleHandleW`, and
the self-test reports a **tri-state** conclusion (`confirmed` / `inconclusive` /
`no_provider`) instead of a false negative.

**This does not close rank 6.** Valkyrie still has no signature engine, cannot
detect what the installed provider cannot, and contributes nothing on a host with
no provider. It borrows a verdict - that is the honest description, and the
efficacy harness deliberately does not score it, because measuring someone else's
engine as Valkyrie's recall is exactly the fake parity this document forbids.

**Next candidates (re-ranked)**: (a) **VM detonation lab** - build/test-sign the
kernel driver (ADR 0026/0031) and run the Atomic Red Team harness in `redteam/`
against a live agent; this is now the top gap, because the driver has never been
compiled and the sensor-capture dimension has never been measured; (b) AMSI file
scanning wired to process images the behavioural layers already flagged
(conviction as corroborator); (c) vulnerability visibility (installed software vs
local CVE feed); (d) browser protection via TLS-inspector + URLhaus full URLs.

## Cycle 2026-08-04: closing the measured Tier A gaps - SHIPPED
ADR 0041. Driven by `redteam/evaluation/`'s own root-cause output rather than a
fresh survey: the evaluation had already named a concrete code fix per miss, so
this cycle executed the subset needing no new infrastructure.

- **Reconnaissance burst** (Discovery 17% -> 83%): `classify_discovery` attaches
  an INFO-only `discovery_command` label; the new `reconnaissance-burst` sequence
  IOA fires (MEDIUM) only on **>=3 DISTINCT** discovery techniques from one
  lineage in 120s. Needed a new `Step.min_distinct` capability - the sequence
  engine could previously express only *order*, never *breadth*. A lone `whoami`
  still raises nothing, by design. Also wired `classify_discovery` into
  `etw/sysmon.py` EID 1 (and therefore Security/4688), because these commands
  exit in milliseconds and the 2s poller loses them - correct logic behind a dead
  delivery path is not detection.
- **T1489 service stop/disable** (Impact 67% -> 100%) and **T1570 lateral tool
  transfer**: real coverage holes, now two + one rules, each with `cmd_all` verb
  pinning and benign regression controls (`sc stop Spooler`, `sc query WinDefend`,
  UNC copy to a non-admin share).
- **Browser credential-store watch** (`browser_cred_watch.py`, T1555.003):
  polls open file **handles** against the known browser password stores instead
  of a command-line rule - catches a compiled stealer that has nothing revealing
  on its command line. HIGH with no corroboration (owning browsers excluded).
- **Threat-intel feeds default ON** (`USE_EXTERNAL_LISTS` False -> True, new
  `--no-download-lists` opt-out). Feodo/URLhaus/ThreatFox were silent no-ops
  unless the user knew to pass a flag. Matching stays 100% local; only the
  periodic fetch is affected.
- **Path-level URL blocking** (the extension seam ADR 0015 left open): new `url`
  indicator kind + `normalize_url` + `match_url`, enforced in `tls_addon.py`.
  Matching is **exact**, never parent-based - malware lives on compromised
  legitimate sites, so blocking the parent domain off one bad path would be the
  false positive.

**Measured: Tier A 25/40 (62.5%) -> 32/40 (80.0%)**; efficacy gate held at
100% recall / 0% FPR; 35 -> 38 IOA rules, 5 -> 6 sequence IOAs.

**Honest boundaries (unchanged):** Tier A is still classifier-input replay, not a
live attack - **Tier B has still never been run**, and that number will be worse.
Discovery hits are scored as burst *contributors*, not standalone alerts. The
credential watch is a 5s poll, not a minifilter. Real-time discovery delivery
needs Sysmon or 4688 auditing. URL blocking needs the opt-in TLS inspector.

**Next candidates (unchanged at the top)**: (a) **VM detonation lab** - build and
test-sign the kernel driver (ADR 0026/0031) and run Tier B against a live agent.
This is still the #1 gap and nothing in this cycle moved it: the driver has never
been compiled, and prevention (as opposed to detect-and-respond) does not exist
until it is. (b) AMSI file scanning as a corroborator on already-flagged images;
(c) vulnerability visibility vs a local CVE feed.
