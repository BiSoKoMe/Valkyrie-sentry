# Threat Landscape Research — August 2026

Research pass over the current public threat landscape, mapped against Valkyrie's
existing detection surface. Sources are public vendor reporting and research from
Jan–Aug 2026; each claim carries its source inline.

**Honesty boundary, up front:** everything below is *coverage* analysis — which
attacker behaviours Valkyrie has rule content for. Coverage is not detection rate.
The only real Tier B (live VM + Atomic Red Team) result on record remains 1/40.
Nothing in this document changes that number, and no rule added off the back of it
should be described as a detection until it fires on a live run.

---

## 1. What actually moved this year

### Initial access is bought, not earned

Prior compromise now accounts for **30% of initial infection vectors, doubled from
15%** the previous year (M-Trends 2026). That is the Initial Access Broker economy
becoming the dominant front door. Access is transferred between actors **in under
30 seconds**, so the gap between "someone got a foothold" and "ransomware operator
is driving" has effectively closed. IABs have shifted focus toward **RDWeb portals**
as public RDP exposure got squeezed.

Consequence for a host-based product: the interesting window is no longer the
exploit. It is the first ten minutes of hands-on-keyboard activity by an operator
who bought the box.

### ClickFix went from novelty to the front door

Fake-CAPTCHA paste-and-run was **the number one initial access method of 2025 at 47%
of observed attacks** (Microsoft), and Red Canary's 2026 Threat Detection Report
ranks **Malicious Copy and Paste (T1204.004)** in its top ten techniques for the
first time. The user is socially engineered into pasting a command into the Run
dialog themselves — no browser bug is ever exploited, which is exactly why it
survives patching. 2026 variants pull C2 from on-chain storage (EtherHiding) and the
technique has crossed to macOS, where a Terminal paste bypasses Gatekeeper by
explicit user action (Sophos, Microsoft).

### Stealers moved decryption off the endpoint

This is the single most important shift for endpoint telemetry. A stealer called
**Storm**, surfacing in early 2026, **stopped decrypting browser credential stores
locally and instead ships the encrypted files to attacker infrastructure for
server-side decryption** (BleepingComputer, Varonis). That deliberately removes the
DPAPI/decryption telemetry most endpoint tooling keys on. The detectable act becomes
bulk file access and egress, not credential decryption.

Alongside this, **session cookies have displaced passwords** as the target — a
stolen cookie loaded into the attacker's browser bypasses MFA entirely. macOS is no
longer an afterthought: infostealers are the largest category of new macOS malware
(+101% over two quarters), with AMOS/Atomic distributed through cracked apps,
malvertising, ClickFix prompts, and — in Feb 2026 — **malicious agent skills on
OpenClaw** (Trend Micro).

### The browser is the endpoint

Red Canary's 2026 report is blunt that most top threats **either execute from the
browser or steal browser-stored data**. Extension campaigns in 2026 alone: five
coordinated Chrome extensions impersonating Workday/NetSuite/SAP tooling that
**exfiltrated auth cookies every 60 seconds** (Socket, Jan 2026); **119 Edge
extensions across ~2.6M installs** hiding payloads inside image and font files
(Microsoft); a fake Perplexity extension routing every keystroke in the address bar
to an attacker server; **40 malicious Firefox Web3 extensions** (Aug 2026); and 77
add-ons in the "Offside" wallet-theft cluster.

### EDR evasion industrialised

**BYOVD is now shipped as a product feature.** As of March 2026, **54 distinct EDR
killer tools abuse 35 signed vulnerable drivers**. ESET documented **Gentlemen**, a
RaaS that centrally develops "GentleKiller" and ships it to every affiliate at
onboarding rather than leaving evasion to them. **Reynolds** ransomware (Feb 2026)
embedded a vulnerable NsecSoft driver (CVE-2025-68947) *inside the payload*,
collapsing the separate EDR-kill stage entirely.

A newer **driverless** class matters just as much: **EDRSilencer** blocks the
security agent's outbound traffic via Windows Filtering Platform, and **EDR-Freeze**
suspends it into a coma. Neither loads a driver, so driver-load telemetry never
fires.

### AI crossed from tooling to operator

**JadePuffer** (Sysdig, July 2026) is documented as the first ransomware operation
run **end-to-end by an autonomous agent** — reconnaissance, credential theft,
lateral movement, persistence, privilege escalation, and encryption, chained without
a human, after initial access through a Langflow vulnerability. It harvested LLM
provider keys, multi-cloud credentials, wallets, and DB creds. Unit 42 measures
agents completing the **full ransomware lifecycle in ~25 minutes**. Notably, the
agent **narrates its own intent the entire way** — which is a detection opportunity,
not just a threat.

### Supply chain became self-replicating

Six confirmed campaigns hit npm, PyPI, Go modules, and Packagist between March and
July 2026. **axios** was turned into a cross-platform RAT delivery system for ~3
hours on 31 March via one compromised maintainer account. **LiteLLM** on PyPI was
poisoned to harvest AWS/GCP/Azure tokens, SSH keys, and Kubernetes credentials. The
**Mini Shai-Hulud** worm produced the first malicious npm packages carrying **valid
SLSA provenance**, and its source release on 12 May spawned copycats — a single worm
event now out-volumes a quarter's worth of manual campaigns. **TrapDoor** was the
first to weaponise npm, PyPI, and Crates.io simultaneously with per-runtime
execution paths.

### Living off the land, now with new interpreters

LOLBins appeared in **17% of investigations in Q3 2025, up from 13%**, and
**PowerShell features in 71% of LOTL attacks**. The 2026 evolution is adversaries
moving to **Node.js, Deno, and Python** precisely because those execution patterns
are less baselined, plus continued heavy use of **DLL sideloading** (HijackLoader
ships as a ZIP of legitimate EXE + malicious DLL).

**RMM abuse surged 277%** and Red Canary now calls RMM tooling the **preferred
payload** across diverse actors. January 2026 saw attackers daisy-chain Action1 to
push ScreenConnect via MSI — legitimate signed deployment tooling all the way down.
An attacker on AnyDesk is, to an EDR, indistinguishable from the helpdesk.

### Privacy-side tracking (Valkyrie's actual mission)

**Over thirty distinct fingerprinting techniques** are deployed against Chrome
users, and fingerprinting has **replaced cookies as the primary tracking vector**
for most ad-tech. CNAME cloaking continues to alias trackers onto first-party
subdomains to defeat DNS-level blocking, and server-side tagging moves collection
off the client entirely — recent academic work (SST-Guard) characterises server-side
Google Analytics in the wild. Fingerprint accuracy is reported at ~98% within 10
minutes, decaying to ~50% over 3–24 hours, which tells you re-identification is a
*session-scale* problem, not a permanent-ID problem.

---

## 2. Mapping to Valkyrie

Verified against `valkyrie/behavioral_rules.py` (166 rules),
`valkyrie/behavioral_sequences.py`, `valkyrie/behavior_score.py`, and
`valkyrie/etw/sysmon.py`.

### Already covered

| Landscape item | Valkyrie coverage |
|---|---|
| ClickFix / paste-and-run | `clickfix-run-dialog-exec`, T1204.004, explorer-parent + download/hidden markers — `behavioral_rules.py:1104` |
| BYOVD driver load | ETW EID 6, list-free: unsigned **or** dropped-dir driver — `etw/sysmon.py:261` |
| Browser credential store theft | `cred_browser`, copies of Login Data / logins.json / key4.db / cookies.sqlite — `behavioral_rules.py:771` |
| .NET profiler hijack | `cor-profiler-hijack`, T1574.012 — `behavioral_rules.py:873` |
| CNAME-cloaked trackers | `cname_uncloak.py` |
| Fingerprinting defence | `farble.py`, `fingerprint.py`, `mac_randomizer.py` |
| DGA / DoH / DNS tunnelling C2 | `dga.py`, `doh_detector.py`, `dns_tunnel.py` |
| Ransomware behaviour | `ransomware_shield.py` + recovery-inhibition rules |

### Real gaps, ranked

**1. RMM abuse (T1219) — zero coverage.** Grep returns nothing for ScreenConnect,
AnyDesk, Atera, RustDesk, TeamViewer, or T1219 anywhere in the rule set. (The 22
`atera` hits are substring matches inside "lateral".) This is the single widest gap
relative to the landscape: it is Red Canary's *preferred payload* finding, +277%
growth, and it maps directly onto Valkyrie's privacy mission because an RMM session
is total observation of the user's machine.

**2. Bulk browser-profile exfiltration — partial, and on the wrong side of the
shift.** The existing `cred_browser` rule catches copying the *named SQLite stores*.
Storm-class stealers that archive the whole profile directory and ship it encrypted
for server-side decryption will not necessarily hit those filename markers, and by
design produce no local decryption telemetry. The generalizing signal is
archive-then-egress over a browser profile path, not the filenames.

**3. Malicious browser extension load — partial structural coverage.** Imported
Sigma content already detects Chromium launched with `--load-extension`. The
August 2026 integrity increment additionally observes targeted Sysmon file writes
inside Chromium/Firefox extension stores, non-browser modification of Chromium
Preferences files, and writes to `ExtensionInstallForcelist` or
`ExtensionSettings`. It grades the change by writer provenance and retains no
registry payload or extension source. This is mechanism coverage, not proof that
Valkyrie can identify a store-delivered malicious extension or its runtime intent.
See `BROWSER_EXTENSION_INTEGRITY.md`.

**4. Driverless EDR killers — zero coverage.** `etw/sysmon.py` covers the driver-load
path only. EDRSilencer-style WFP filter additions and EDR-Freeze-style process
suspension bypass that entirely.

**5. Node.js / Deno / Bun as attacker interpreters — worse than zero.** `node.exe`
currently appears only in `behavior_score.py:145` in the *benign long-running server
process* list, i.e. it is presently a **suppressor**. If adversaries are moving to
Node.js specifically to evade baselining, that entry is an inversion risk worth
re-examining. Deno and Bun are absent entirely.

**6. DLL sideloading (T1574.001/.002) — zero.** Only the `.012` COR_PROFILER variant
is covered. HijackLoader's signed-EXE-plus-evil-DLL-in-a-ZIP shape is untouched.

**7. Package-manager postinstall execution — zero.** No rule for npm/pip/cargo
spawning a network-capable child during install, which is the common execution
moment across every 2026 supply-chain campaign.

---

## 3. Recommended order of work

Ranked by mission fit × visibility in telemetry Valkyrie already has × how well the
rule generalizes rather than lists.

1. **Measure browser extension integrity efficacy** — the classifier and narrowed
   Sysmon configuration now have live mechanism validation on a disposable
   Windows runner. Malicious-extension efficacy and false-positive volume remain
   unmeasured.
2. **RMM install/execution IOA** — behavioural shape (unattended install → service
   → outbound to relay) rather than a vendor name list, so it survives new RMM
   products.
3. **Profile-archive-then-egress sequence** — closes the Storm-class gap in
   `behavioral_sequences.py` where it belongs, as a sequence not a rule.
4. **Driverless EDR-kill signals** — WFP filter add + targeted suspend.
5. **Non-native interpreter execution** — and revisit the `node.exe` suppressor.
6. **DLL sideload** and **package postinstall** — lower priority, weaker signal in
   current telemetry.

Every one of these must clear the standing bar before it counts: generalizing rule
content, held-out bypass attempt, 0 FP on the benign battery, permanent regression
test, and honest labelling about what layer actually observes it.

---

## Sources

M-Trends 2026 · Rapid7 2026 Global Threat Landscape · Unit 42 2026 Global IR Report
· Securelist State of Ransomware 2026 · Red Canary 2026 Threat Detection Report ·
Microsoft Security Blog (macOS/Python stealers, Feb 2026; signed RMM backdoors, Mar
2026) · BleepingComputer & Varonis (Storm, 2026) · The Hacker News (54 EDR killers,
Mar 2026; 40 Firefox Web3 extensions, Aug 2026) · ESET via SOC Prime (Gentlemen /
GentleKiller, Jun 2026) · Sysdig via CSA Labs (JadePuffer, Jul 2026) · Zscaler
ThreatLabz (axios/LiteLLM, Mar 2026) · Phoenix Security (supply chain 2026) ·
Huntress 2026 Cyber Threat Report (RMM) · Trend Micro (AMOS via OpenClaw skills,
Feb 2026) · Sophos (ClickFix + macOS stealers) · Socket via centrexIT (Chrome HR/ERP
extensions, Jan 2026) · Push Security (browser threat mid-year 2026) · arXiv
2604.27497 (SST-Guard, server-side tracking)
