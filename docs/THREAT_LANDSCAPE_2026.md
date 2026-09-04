# Threat Landscape Reference (2026)

**Source note:** written from the author's trained knowledge (current through
January 2026), not live-fetched web research — this session's web/agent tools
were unavailable when this was written. Treat named campaigns/tools as
"well-established as of early 2026," not "verified this week." Re-validate
anything time-sensitive (a specific group's current TTPs, a CVE's patch
status) before using it operationally.

**Purpose:** a working reference for Valkyrie's own development — attacker
technique, mapped to a concrete host-observable signal, mapped to what
Valkyrie already has or is missing. Not a general security 101 document.
Every section ends with a "Valkyrie today" note. Per standing project
direction, none of this recommends AI/ML/LLM-based detection as the answer —
Valkyrie's whole position is classical, explainable, behavior/rule-based
detection.

---

## 1. Framework: how this document is organized

MITRE ATT&CK (Enterprise matrix) is the shared vocabulary — Tactics (the
*why*: Initial Access, Execution, Persistence, Privilege Escalation, Defense
Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2,
Exfiltration, Impact) and Techniques/sub-techniques (the *how*, e.g.
T1055.012 Process Hollowing). Valkyrie's own rule catalog
(`valkyrie/behavioral_rules.py`, `redteam/evaluation/catalog.py`) is already
organized this way, so this doc uses the same IDs throughout.

The **cyber kill chain** (Lockheed Martin's older, coarser model) still
matters conversationally: Recon → Weaponize → Deliver → Exploit → Install →
C2 → Actions on Objectives. ATT&CK is the detection-engineering-grade version
of the same idea.

---

## 2. Malware taxonomy

### Ransomware
Modern ransomware operations are rarely "just encryption" — the dominant
pattern since ~2021 is **double extortion** (encrypt + exfiltrate, threaten
to leak) and increasingly **triple extortion** (also DDoS the victim, or
directly pressure the victim's customers/partners). Notable families/groups
across recent years: LockBit (RaaS, affiliate model, went through law-
enforcement disruption but variants persist), BlackCat/ALPHV (Rust-based,
cross-platform), Akira, Cl0p (known for mass exploitation of file-transfer
software — MOVEit, GoAnywhere — rather than phishing), Play, BianLian (pivot
to pure-exfiltration-no-encryption extortion). Common technical pattern
regardless of brand:
1. Initial access via phishing, exposed RDP, or an unpatched edge appliance/
   file-transfer product.
2. Credential theft + lateral movement to reach a domain controller or
   backup infrastructure specifically (backups are a deliberate target,
   not incidental).
3. **Shadow copy / backup destruction** immediately before encryption
   (`vssadmin delete shadows`, `wbadmin delete catalog`, `wmic shadowcopy
   delete`) — this step is close to universal and highly detectable.
4. Mass file encryption, usually via a fast stream cipher (ChaCha20 is
   common) with the key wrapped by an embedded RSA/ECC public key.
5. Ransom note drop + sometimes wallpaper change.

**Valkyrie today:** `ransomware_shield.py` (canary-file tripwire) + the
shadow-copy-deletion rule already cover steps 3-4 of this chain directly,
and the live-fire log shows `impact-ransomware-encrypt` as a confirmed live
DETECT. The double-extortion **exfiltration** half of the chain is the
weaker-covered side — Valkyrie's collection/staging rules
(`collection_staging` canonical behavior) exist but a dedicated "large
archive created then network egress within N minutes" burst-correlation
(mirroring `behavioral_sequences.py`'s existing `creds-then-exfil` pattern)
would be a natural, cheap extension: `stage-then-exfil` analogous to the
existing credential one.

### Infostealers
The single most relevant malware class for a **privacy-focused** EDR.
RedLine, Vidar, Lumma, Raccoon, and similar "stealer-as-a-service" families
are commodity, cheaply rented, and share a near-identical playbook:
1. Delivered via cracked-software sites, fake CAPTCHA/"ClickFix" pages
   (paste-and-run PowerShell — Valkyrie already has a `clickfix-run-dialog`
   rule per the rule list read earlier this session), or malvertising.
2. On execution: enumerate and copy browser credential stores (Chrome/Edge
   `Login Data` SQLite DB + the DPAPI-protected master key, cookies
   `Cookies` DB for session-token theft — session-cookie theft is now often
   MORE valuable to an attacker than a password, since it can bypass MFA
   entirely), crypto wallet files, Discord/Telegram session tokens, and
   system fingerprint info (this is a directly Nyx-relevant behavior class —
   fingerprinting for resale/tracking overlaps mechanically with what
   legitimate trackers do, which is part of why Nyx's "not just an
   allowlist" design already generalizes here).
3. Archive the loot, exfiltrate over HTTPS to a C2 panel or a Telegram bot
   API endpoint (this specific pattern — POST to `api.telegram.org` from an
   unusual process — is a well-known, narrow, high-precision detection
   opportunity many EDRs implement explicitly).
4. Often self-deletes after exfiltration (anti-forensics, not sophistication
   — just cheap to add).

**Valkyrid today:** `cred_browser`/`credential_store_access`/
`collection_archive_creds` canonical behaviors and several named rules
already target exactly this (per `behavior_ontology.py`'s
`_CREDENTIAL_ACCESS_ATTEMPT` set read earlier this session). The Telegram-
API-as-exfil-channel pattern specifically is worth checking whether it's
covered under the existing network/C2 detection or would be a new, narrow,
low-FP-risk rule (a process that is not a browser POSTing to
`api.telegram.org` is a strong, cheap signal).

### RATs (Remote Access Trojans)
AsyncRAT, njRAT, QuasarRAT, Remcos — mostly commodity, .NET-based, persist
via Run keys or scheduled tasks, communicate over a custom TCP protocol or
HTTP polling, and give full remote-hands-on-keyboard control (keylogging,
screen capture, file transfer, shell access). Less architecturally
interesting than infostealers/ransomware, but persistence + C2-beacon
behavior overlaps heavily with what Valkyrie already targets structurally.

### Rootkits / bootkits
Kernel-mode rootkits (hook SSDT/IDT, or more commonly today, since PatchGuard
makes classic SSDT hooking impractical on x64, abuse a **signed, vulnerable
third-party driver** — BYOVD, covered in detail in §3) to hide processes/
files/registry keys from usermode tools, or to directly kill security
software. Bootkits (BlackLotus is the most consequential recent example —
a UEFI bootkit that bypassed Secure Boot via a signed-but-vulnerable
bootloader) persist below the OS entirely, surviving a reinstall.
**Valkyrie today:** this class is structurally out of reach for a usermode-
plus-single-kernel-driver product without Secure Boot/UEFI-level tooling —
correctly scoped as a known limitation, not a gap to chase. The driver's own
`README.md`/`BRINGUP.md` are honest about this (no PPL, no minifilter, no
WFP), which is the right posture.

### Wipers
Destructive, no ransom motive — HermeticWiper/CaddyWiper-class tools (seen
heavily in the Russia/Ukraine conflict) either corrupt the MBR/partition
table directly or overwrite files with garbage. Detection signal overlaps
almost entirely with ransomware's destructive-impact behaviors
(`destructive_impact` canonical behavior already exists) — mass file
overwrite + disk-level access from an unusual process.

### Cryptominers
Low-sophistication, high-volume, usually dropped as a secondary payload
after an initial compromise (or via a vulnerable public-facing service).
Detection signal: sustained near-100% CPU from an unsigned/unusual binary,
often with a `stratum+tcp://` mining-pool connection string in cmdline or
network destination — a narrow, cheap, high-precision rule if not already
present.

### Fileless malware
"Fileless" is a slight misnomer — it means no malicious binary ever touches
disk as a discrete file, not that nothing is written anywhere. Mechanisms:
reflective DLL injection (payload loaded directly into memory from network/
registry, never disk), PowerShell/WMI-resident payloads (stored in a WMI
class property or a registry value, executed via a scheduled task or WMI
event subscription that never references a file path), and .NET
`Assembly.Load(byte[])` from an in-memory buffer. This is precisely why
process-lineage + cmdline + injection-primitive detection (Valkyrie's actual
architecture) matters more than a file-hash/signature approach — fileless
malware is invisible to anything that only scans files.

### Supply-chain compromise
npm/PyPI/RubyGems package-name-squatting or maintainer-account takeover,
malicious postinstall scripts, or (higher-end) a compromised build pipeline
injecting a backdoor into a legitimately-signed product (SolarWinds remains
the canonical example). Detection is genuinely hard at the host level once
the payload is running as part of a trusted process — the realistic
detection point is the **behavior** the injected code then performs (network
beacon, credential access, persistence), not recognizing the supply-chain
vector itself.

---

## 3. EDR evasion & anti-detection techniques (the attacker-vs-EDR arms race)

This is the most directly relevant section for a product whose entire job is
surviving this arms race.

**AMSI bypass.** AMSI (Antimalware Scan Interface) lets AV/EDR inspect a
script's content just before execution (PowerShell, VBA, JScript). Attacker
techniques, roughly in order of sophistication: (a) obfuscation/string-
splitting to defeat simple signature scanning of the AMSI buffer content
itself — weak, still works against naive scanners; (b) patching
`amsi.dll!AmsiScanBuffer` in the process's own memory to always return
"clean" (the classic `[Ref].Assembly.GetType('...AmsiUtils')` PowerShell
one-liner — Valkyrie already has a rule for exactly this string, per the
`amsi-bypass` rule read this session); (c) forcing `amsiInitFailed` via a
context flag so AMSI never initializes for that process at all;
(d) downgrade attacks (force PowerShell v2, which predates AMSI entirely).
**Detection signal:** the memory-patch variant is the strongest — a write to
`amsi.dll`'s own code pages from within the hosting process is a very high-
precision signal (near-zero legitimate reason for this) if the sensor can
see it; short of that, the cmdline-string signal Valkyrie already has is the
practical fallback and is genuinely effective against the common case.

**ETW patching/blinding.** Directly analogous to AMSI bypass but targets
`ntdll!EtwEventWrite` — patch it to return immediately without emitting the
event, blinding EVERY ETW-based consumer (this is exactly the transport
Valkyrie's own sensors — Sysmon, native process auditing — depend on).
**Detection signal:** structurally hard to detect FROM userland ETW itself
(if ETW is blind, it's blind) — the correct backstop is a kernel-mode
signal that doesn't route through the same disableable path (a
`PsSetCreateProcessNotifyRoutineEx` kernel callback, which is what
Valkyrie's own driver provides, keeps working even if userland ETW is
patched — this is a concrete, already-partially-built answer worth being
explicit about in the driver's own value proposition).

**Direct/indirect syscalls.** Userland EDR hooks typically live in
`ntdll.dll`'s exported functions (inline hooks on `NtCreateFile`,
`NtAllocateVirtualMemory`, etc.). Attackers bypass this by either (a)
manually crafting the `syscall` instruction with the right syscall number,
skipping the hooked ntdll wrapper entirely (direct syscalls — tools like
SysWhispers generate this), or (b) "indirect syscalls" (jump into an
unhooked region of ntdll that itself contains the `syscall` instruction, to
also evade a naive "does this thread's return address point outside a
known module" check). **Detection signal:** this specifically defeats
userland API hooking — it does NOT defeat a kernel-mode ObRegisterCallbacks
or process/thread-notify-routine signal, since those fire regardless of how
usermode reached the syscall. This is the single strongest argument for why
Valkyrie's kernel driver work this session matters architecturally, not
just as a checkbox — it's immune to this whole evasion class by
construction.

**Process injection (the full menu, since ATT&CK T1055 has many
sub-techniques):** classic (`OpenProcess` + `VirtualAllocEx` +
`WriteProcessMemory` + `CreateRemoteThread`), process hollowing (spawn a
legitimate process suspended, unmap its image, write a malicious one into
the same address space, resume), APC injection / "Early Bird" (queue an APC
to a thread before it starts running, so the payload runs before any EDR
hook in that process's init path), thread hijacking (suspend an EXISTING
thread in a target process, redirect its instruction pointer, resume —
avoids `CreateRemoteThread` entirely, which is itself a heavily-monitored
API), module stomping (overwrite an already-loaded, legitimate DLL's memory
with the payload, so no new suspicious memory region ever gets allocated),
and transacted hollowing (use NTFS transactions so the on-disk file briefly
contains the payload only inside an uncommitted transaction, evading
disk-scanning AV entirely). **Valkyrie today:** `remote_thread`/
`process_injection` canonical behaviors + the `T1055` sequence step
already exist; the driver's thread-create-notify callback is architecturally
the right primitive for the harder variants (APC/thread-hijack) that never
call the heavily-watched `CreateRemoteThread`.

**BYOVD (Bring Your Own Vulnerable Driver).** The dominant technique for
killing EDR/AV from kernel space in 2024-2026: rather than write a new
malicious kernel driver (hard to get signed, easy to flag), load a
legitimately-signed but VULNERABLE third-party driver (dozens of real
examples exist — vendor driver CVEs get reused across many campaigns once
public) that exposes a raw physical-memory-read/write or arbitrary-kernel-
call primitive, then use that primitive to directly unlink/disable the
target EDR's own driver or kill its process with kernel privileges,
bypassing PPL entirely. Tools like "AuKill"/EDRSilencer packaged this into
push-button form. **Detection signal:** a NEW, unusual kernel driver being
loaded (especially one with a history of being abused, which Microsoft's
own vulnerable-driver blocklist — HVCI/Smart App Control's blocklist —
tracks) is the practical signal; Valkyrie's own driver load-image-notify
callback is the right primitive, and Microsoft's public vulnerable-driver
hash blocklist is a legitimately reusable, low-maintenance IOC source worth
checking whether Valkyrie already consumes.

**LOLBins (Living-Off-the-Land Binaries).** Using legitimate, signed
Windows/OS-vendor binaries for malicious ends specifically to blend in:
`rundll32`/`regsvr32`/`mshta` for script-proxy execution, `certutil` for
download-and-decode, `bitsadmin`/`BITS` jobs for stealthy download,
`msbuild`/`installutil`/`regasm` for signed-binary code execution
(T1218-family), `wmic`/PowerShell `Invoke-CimMethod` for remote process
creation. LOLBAS project (lolbas-project.github.io conceptually, not a
live-fetched link) catalogs these exhaustively. **Valkyrie today:** this is
already the single most-covered category in the existing rule set (per the
rules read this session — certutil, bitsadmin, mshta, regsvr32, rundll32
all present) — this is a strength, not a gap.

**Timestomping & masquerading.** Changing a file's MACE timestamps to blend
with surrounding legitimate files (defeats naive "recently created file"
triage), and masquerading (naming/placing a malicious binary to look like a
system one — `svchost.exe` running from `C:\Windows\Temp` instead of
`System32`, or literally renaming `cmd.exe` to `lsass.exe`). **Valkyrie
today:** already covered per the `masquerade-system-binary-location` rule
and this session's own fix work (T1036.003 vs .005 disambiguation).

---

## 4. Credential access, beyond basic LSASS dumping

- **LSASS dumping variants:** `comsvcs.dll,MiniDump` (already covered),
  Task Manager's own "Create dump file" GUI action (produces an identical
  artifact, no attacker tooling needed at all — worth confirming this path
  is covered, since it bypasses every cmdline-based rule), handle
  duplication (steal an EXISTING handle another process already holds to
  lsass, rather than opening a new one — defeats a naive
  "block OpenProcess to lsass" mitigation, though NOT Valkyrie's driver's
  actual approach of stripping rights on issued handles), and cloud/
  snapshot-based dumping (suspend a VM/container and read memory from the
  hypervisor level — out of scope for a single-host EDR by construction).
- **Kerberoasting / AS-REP roasting:** request a service ticket (or, for
  AS-REP, target an account with pre-auth disabled) for any SPN-registered
  domain account, then crack the ticket's encrypted portion offline —
  entirely on-the-wire/AD-side, no host malware artifact at all. Detection
  lives in AD/domain-controller telemetry (unusual volume of TGS-REQ
  requests, e.g. via `Rubeus`), which is structurally outside a
  single-endpoint product's visibility — correctly out of scope for
  Valkyrie, worth stating explicitly as a limitation rather than silently
  gapped.
- **DPAPI abuse:** Windows' Data Protection API encrypts saved
  credentials/cookies/Wi-Fi keys tied to the user's login secret. Tools
  (Mimikatz's `dpapi::` modules, SharpDPAPI) extract the machine or user
  DPAPI master key to decrypt ANY DPAPI blob offline — this is the actual
  mechanism behind most "browser stole my saved passwords" infostealer
  behavior in §2, not a separate exotic technique.
- **Token theft/impersonation:** duplicate an existing token from a
  higher-privileged process (`SeDebugPrivilege` + `DuplicateTokenEx`) to
  run code AS that user/SYSTEM without ever touching a password or hash —
  this is the actual mechanism behind many "privilege escalation" tool
  chains (`Incognito`, `PsExec -s` reuse patterns).

---

## 5. C2 frameworks & network-level evasion

Cobalt Strike remains the dominant commercial red-team/actual-attacker
framework (cracked/leaked versions circulate widely); Sliver (open-source,
Go-based, cross-platform) and Mythic (modular, plugin-based) have grown as
Cobalt Strike alternatives, partly BECAUSE Cobalt Strike's traffic patterns
are now extremely well fingerprinted by defenders (default Malleable C2
profiles, JA3/JA3S TLS fingerprints, specific beacon HTTP header shapes)
— all three frameworks let an operator customize traffic shape specifically
to evade this fingerprinting, which is an ongoing arms race, not a solved
problem on the defender side.

- **Domain fronting / CDN abuse:** route C2 traffic through a legitimate,
  reputable CDN (Cloudflare, Azure Front Door, Fastly) so the SNI/DNS the
  network sees is for a trusted domain, while the actual HTTP Host header
  (only visible if TLS is terminated/inspected) points to the real C2 —
  defeats domain-reputation/IP-blocklist defenses that key off DNS/SNI
  alone.
- **Living-off-trusted-sites C2:** use Slack, Discord, Microsoft Teams,
  GitHub Gists, or Telegram's Bot API as the actual C2 transport — traffic
  goes to a domain every allowlist already trusts, and blocking it means
  blocking a service the business actually uses. Same class of problem as
  the infostealer-exfil-via-Telegram pattern in §2.
- **Sleep-mask / jitter:** modern beacons encrypt themselves in memory
  while "sleeping" between check-ins (defeats memory-scanning while idle)
  and randomize check-in intervals (defeats simple "beacon every exactly
  60s" periodicity detection) — this directly targets exactly the kind of
  network-behavior anomaly scoring Valkyrie's own network layer does
  (per this session's earlier discussion of `network_score.py`'s
  `never_resolved` signal), meaning periodicity-based detection alone is a
  known-weak signal against a competent operator; destination reputation +
  DNS-resolution-history signals (which Valkyrie already has) are more
  jitter-resistant than periodicity is.

---

## 6. Defensive / EDR architecture — how the other side actually works

**Telemetry sources, roughly in order of how hard they are to blind:**
1. **Usermode API hooking** (inline hooks in ntdll, DLL injection into every
   process) — cheapest to build, easiest to evade (unhooking, direct
   syscalls, as above). Most commercial AV historically started here.
2. **ETW (Event Tracing for Windows)** — kernel-emitted, consumed in
   userland; far more evasion-resistant than API hooking, but still
   blindable via the ETW-patching technique in §3, and depends on the
   provider actually being enabled (Sysmon's own config, or native
   Security-4688 auditing, both need explicit enablement — exactly the gap
   Valkyrie's own `native_audit.py` auto-enables at startup, and exactly
   why `demo_readiness.py`'s "command-line eye" check exists).
3. **Kernel callbacks** (`PsSetCreateProcessNotifyRoutineEx`,
   `PsSetLoadImageNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`,
   `ObRegisterCallbacks` for handle operations, `CmRegisterCallback` for
   registry) — what Valkyrie's own `valkyrie_km.sys` implements. Survives
   ETW-patching and usermode unhooking by construction, since it's a
   different, kernel-resident code path entirely.
4. **Minifilter drivers** (file-system I/O interception — every
   create/read/write/rename at the kernel level, BEFORE the operation
   completes, which is what makes real-time ransomware-encryption
   *prevention* (not just detection-after-the-fact) possible) — Valkyrie
   does NOT have this (explicitly documented as a gap in `driver/README.md`
   read this session).
5. **WFP (Windows Filtering Platform) callouts** (kernel-level network
   packet/connection interception, what real firewall products and
   kernel-level network EDR sensors use) — Valkyrie also does not have
   this; its network visibility is userland (`network_telemetry.py` per
   this session's file listing).
6. **ELAM (Early Launch Anti-Malware) + PPL (Protected Process Light)** —
   the mechanism that lets a small set of Microsoft-vetted AV vendors'
   drivers load before third-party drivers at boot, and run their own
   process as a protected process immune to normal `OpenProcess`/handle
   tampering even from an admin. This requires Microsoft's own vetting
   program, not just code — the honest limitation `driver/README.md`
   already states plainly.

**Detection engine styles**, all coexisting in real products, not
mutually exclusive: (a) static signature/hash matching (fast, cheap,
useless against any polymorphism or fileless technique — legacy AV's
original approach); (b) YARA rules (pattern-match across a file's bytes,
still static but far more flexible than a pure hash — good for known-family
identification post-hoc, not great as a first line of defense against novel
code); (c) IOA/behavioral rules (the architecture Valkyrie itself uses —
match on ACTIONS/command shapes rather than file content, inherently more
generalizing); (d) sequence/graph correlation (chain multiple weak signals
into one strong one — Valkyrie's `behavioral_sequences.py` and Detection
Architecture v2's causal-context work this session are exactly this
category); (e) anomaly/statistical scoring (deviation from an established
baseline — Valkyrie's `behavior_score.py` per prior memory). Real EDR
products (CrowdStrike, SentinelOne, Elastic) layer several of these
simultaneously and are honest that no single layer alone is sufficient —
which is exactly Valkyrie's own stated three-layer design per its own ADRs.

**Deception technology.** Honeytokens/honeyfiles/canary tokens (a
convincing-looking fake credential or document that should never legitimately
be accessed — any access IS the detection, with near-zero false-positive
risk by construction) and honeypot services (a fake exposed service that
exists only to be attacked, generating high-confidence alerts). Valkyrie's
`decoys.py` already implements exactly this pattern for the endpoint side,
and Nyx's whole "fake instead of block" design is architecturally the SAME
idea applied to the privacy domain (feed a plausible-looking fake value
instead of either blocking or leaking the real one) — worth naming
explicitly as the same design principle reused across two different
subsystems, since that's a genuinely distinctive, defensible position.

---

## 7. Detection engineering as a practice (not just techniques)

- **Purple teaming** (red + blue collaborating in real time, not
  sequential red-then-blue) is how mature security teams actually validate
  detections — which is structurally what this project's own
  `redteam/evaluation/` Tier B live-fire discipline already is, just
  solo-operated rather than team-based. The discipline (real technique
  execution against a real running defender, honestly scored, gaps logged
  and closed one at a time) is the same discipline CrowdStrike/Palo Alto
  internal detection-engineering teams use, not a lesser home-grown
  version of it.
- **Sigma rules** are the closest thing to an open, vendor-neutral
  standard for sharing detection LOGIC (as opposed to Yara's file-content
  focus or STIX/TAXII's IOC-focus) — a Sigma rule is essentially a
  portable IOA rule. Given Valkyrie already imports Elastic detection
  content (per this session's memory of the "Detection-Content Supply
  Chain" work), Sigma is the same class of reusable external content and
  may already be represented in that import pipeline — worth confirming
  Sigma specifically (not just Elastic's own format) is in the funnel.
- **The detection-to-response gap** is where many vendors' real-world
  efficacy actually lives or dies — a detection that never triggers an
  automated response (kill process, quarantine, isolate host) is a log
  line, not protection. This is exactly the "coverage vs. armed response"
  distinction `demo_readiness.py` already checks explicitly (are the
  critical playbooks in `enforce` mode, not just logging) — a mature,
  correct instinct already built into this project.
- **False-positive cost asymmetry** is the single most important cultural
  lesson from real EDR vendors: a missed detection costs one incident; a
  false positive that breaks a legitimate business workflow costs trust in
  the WHOLE product and gets the vendor uninstalled. Every major vendor's
  public post-mortems (the various "our update broke everyone's machines"
  incidents across the industry) trace back to this asymmetry being
  under-respected. This matches Valkyrie's own repeatedly-stated "zero-FP
  prime directive" exactly — worth recognizing that instinct as
  industry-standard best practice, not over-caution.

---

## 8. Summary: where this points for Valkyrie specifically

Reading the above against what's already known about Valkyrie's current
state (from this session and project memory), the clearest concrete
opportunities are:

1. **Kernel callbacks are Valkyrie's actual structural advantage** against
   the ETW-patching/syscall-hooking evasion class (§3) — this is worth
   stating confidently once the driver is fully validated, not
   undersold as "just LSASS protection."
2. **Exfiltration-side correlation** (large archive → network egress,
   mirroring the existing `creds-then-exfil` sequence) is a cheap,
   high-value addition given how central exfiltration is to both
   ransomware's double-extortion model AND infostealer operations (§2).
3. **A narrow Telegram-Bot-API-as-C2/exfil-channel rule** is a concrete,
   low-effort, low-FP-risk candidate given how common this specific
   pattern is in current commodity infostealer/RAT campaigns (§2, §5).
4. **Microsoft's public vulnerable-driver blocklist** is a legitimately
   reusable, low-maintenance external IOC source directly relevant to the
   BYOVD technique class (§3) that specifically targets EDR/AV — worth
   checking whether it's already consumed anywhere in the threat-intel
   feed pipeline.
5. **Minifilter (file I/O) and WFP (network) kernel visibility remain the
   two largest genuine architectural gaps** relative to full commercial
   EDR parity (§6) — both correctly and honestly documented as absent
   already, not something to quietly claim. Closing either is a
   substantial undertaking (a real minifilter is closer in complexity to
   the process-notify driver already built than an incremental step), not
   a quick win — flagged here as a fact, not a recommendation to start
   immediately.
