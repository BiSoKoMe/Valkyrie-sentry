# How the Ten Major Security Vendors Actually Work — August 2026

Architecture and operating-model research on Palo Alto Networks, CrowdStrike,
Microsoft Security, Fortinet, Zscaler, SentinelOne, Check Point, Cisco, Netskope,
and Trend Micro.

Scope note: this is about *mechanism* — where telemetry comes from, where the verdict
is computed, how detection content gets made and shipped, and how the business
actually runs. Marketing claims are labelled as vendor claims where they could not
be independently corroborated.

---

## 1. The framework: three questions that separate all ten

Every vendor here can be placed by answering three questions. Feature lists blur
them together; these do not.

**Q1 — Where is the verdict computed?** On the endpoint, in a cloud brain, in an
inline proxy, in silicon, or in a data lake after the fact. This is the deepest
architectural commitment any of them makes and it determines offline behaviour,
latency, privacy posture, and what happens when the network is hostile.

**Q2 — What is the primary telemetry?** Process events, network flows, TLS-terminated
traffic, API-side SaaS records, or aggregated third-party logs. This determines what
they can *see*, and therefore what they can never detect regardless of how good the
analytics are.

**Q3 — What is the unit sold?** A per-endpoint agent, a per-user seat, an appliance
plus subscription, a data-ingestion tier, or a managed service. This determines
where R&D money goes, which is why platform architectures track revenue models
almost exactly.

Mapped out:

| Vendor | Verdict computed | Primary telemetry | Unit sold |
|---|---|---|---|
| CrowdStrike | Cloud brain (Threat Graph) | Process/kernel events | Per-endpoint modules |
| SentinelOne | **On agent** | Process/kernel events | Per-endpoint agent |
| Microsoft | Hybrid, cloud-weighted | Everything it already owns (OS, identity, mail, cloud) | Bundled seat (E5) |
| Palo Alto | Data lake, post-ingest | Aggregated first + third party | Ingestion + platform |
| Trend Micro | Data lake + native sensors | Cross-layer native sensors | Credit pool |
| Fortinet | Silicon at the gateway | Network flows | Appliance + FortiGuard sub |
| Check Point | Gateway + shared cloud brain | Network flows | Gateway + blade sub |
| Zscaler | Inline proxy PoP | TLS-terminated traffic | Per-user seat |
| Netskope | Inline proxy PoP (single pass) | TLS-terminated + SaaS API | Per-user seat |
| Cisco | Distributed into the fabric | Network + everything Splunk ingests | Infrastructure + Splunk |

---

## 2. Vendor by vendor

### CrowdStrike — the cloud verdict factory

The canonical modern EDR architecture, and the one everyone else was measured
against for a decade.

**Mechanism.** One lightweight sensor per endpoint. On Windows it is a kernel-mode
driver plus a user-mode service; on Linux it runs in user mode over **eBPF** — a
deliberate move away from kernel modules on that platform. The sensor's job is
mostly *collection and enforcement*, not decision: it streams a normalised event
flow to the CrowdStrike Security Cloud, which correlates and returns verdicts. The
console is 100% cloud; there is no on-prem server tier to run.

**The Threat Graph is the actual product.** It correlates on the order of **2.5
trillion endpoint events per week** globally. The architectural bet is that a
behaviour which looks ambiguous on one machine is unambiguous when you can see the
same pattern land on ten thousand machines in an hour. That is cross-customer
network effect as a detection primitive, and it is the single hardest thing on this
page for anyone else to replicate.

**2026 evolution.** CrowdStrike now describes a **polyglot data store** design —
explicitly rejecting one-database-fits-all. Graph systems handle process lineage,
time-series systems handle state and configuration change, and search systems
(Falcon LogScale) hold full-fidelity events. These are unified by an **Enterprise
Graph** layer of five components: Threat Graph (process lineage), Asset Graph
(systems and identities), Risk Graph (environmental factors), Intel Graph (adversary
intelligence), and LogScale. On top sits a Semantic Data Model for schema
translation, a Global Query Engine using a language they call C-Query, and a Global
Command Engine that translates governed actions into native APIs.

**Charlotte AI** expert agents do detection triage over that unified layer — CrowdStrike
claims correlation across endpoints, identities, vulnerabilities and intel "in
milliseconds across all detections." Their framing of agentic is worth quoting
because it is a real design principle, not just positioning: *response logic should
be constructed from evidence, not selected from templates.*

**Business.** ~$5.25B ARR in FY2026, +24% YoY. Land with endpoint, expand into
identity, cloud, log management, and Falcon Complete (their MDR).

---

### SentinelOne — the on-agent autonomy bet

Architecturally the *opposite* choice from CrowdStrike, and the most relevant of the
ten to a product like Valkyrie.

**Mechanism.** A single agent runs the **entire detection stack locally** —
reputation, Static AI, Behavioral AI, and ActiveEDR — **with or without a cloud
connection**. The Singularity Console is the management brain but is explicitly
**not in the detection critical path**. If the network dies, the endpoint still
detects and still responds. That is a materially different product promise than
"sensor streams to cloud."

**Storyline** is their correlation primitive: every process, file, registry, and
network event on the endpoint is tagged with a **Storyline ID**, so the full attack
chain assembles itself automatically into one narrative rather than being
reconstructed by an analyst from separate alerts. Because Storyline is built
on-agent, correlation survives disconnection too.

**Rollback** is the response differentiator: one-click ransomware rollback restoring
encrypted files from local shadow copies. Note the dependency — it works because the
agent is local and privileged, another consequence of the on-agent architecture.

**Business.** ~$1.12B ARR, growing >30%, the fastest grower at its tier. Purple AI
(their agentic SOC layer) is attached to **more than half of new licences**, which
tells you how fast the agentic layer became table stakes commercially.

---

### Microsoft Security — distribution as architecture

Microsoft's advantage is not a better sensor. It is that they own the operating
system, the identity provider, the mail system, and the cloud, so their telemetry is
free and already there.

**Mechanism.** A lightweight MDE sensor ships in Windows (also macOS, Linux, iOS,
Android, IoT), streaming to Microsoft's cloud. But the endpoint is only one plane.
**Defender XDR** unifies Defender for Endpoint, Identity, Office 365, Cloud Apps,
and Vulnerability Management — meaning a phishing email, the identity it
compromised, and the process it spawned are one incident by construction, not by
integration.

**Sentinel** is the cloud-native SIEM underneath, with KQL as the query language.
**Security Copilot** is embedded in-context inside Defender and Sentinel — it
summarises incidents, drafts KQL, and recommends next steps, with a claimed ~30%
MTTR reduction (vendor figure). In March 2026 Microsoft extended this into agentic
security across Defender, Entra, and Purview.

**Business.** ~$37B in security revenue — larger than every other vendor here by a
wide margin — but bundled inside M365 E5 and Azure. The commercial mechanism is that
security is nearly free *if* you already bought the seat. That bundling is the
competitive weapon; the technology is downstream of it.

---

### Palo Alto Networks — collapse the SOC into one data lake

**Mechanism.** Cortex XSIAM is the strategic centre now. It folds together what were
Cortex Data Lake, Cortex XDR, XSOAR, and Xpanse: ingest and normalise *everything* —
endpoint, network, cloud, identity, first-party and third-party — into a unified
**Cortex Extended Data Lake (XDL)**, then run analytics over the whole thing to
deliver SIEM, XDR, SOAR, threat intel, email security, and exposure management as one
surface.

**The bet is data quality over algorithm cleverness.** Their own framing: start with
**triple the EDR telemetry** plus enriched firewall logs, then apply **2,900+ ML
models** (both vendor claims). The pitch is explicitly that better raw data beats
better models on thinner data — which is a defensible position and the same argument
CrowdStrike makes about scale.

**Cortex Agentic Assistant** is the autonomous layer: AI agents that plan, reason,
and investigate multi-domain threats like cloud identity theft or container
breaches, compressing thousands of alerts into a few prioritised cases with root
cause attached.

**Business.** First pure-play security vendor past **$10B ARR**; $5.6B of that
next-gen security ARR in FY2025, +32% YoY. "Platformization" — displacing many point
products with one platform, sometimes by eating the incumbent contract cost — is the
explicit go-to-market.

**Unit 42** is the research and IR arm, and its function is structural rather than
promotional: researchers work directly with product engineering to convert
investigation findings into shipped detection content.

---

### Trend Micro — breadth of native sensor plus a vulnerability pipeline

**Mechanism.** Trend Vision One centralises cyber risk exposure management, security
operations, and layered protection. It positions on **native sensor breadth** —
email, endpoint, server, cloud workload, network — arguing that natively-collected
telemetry correlates better than ingested third-party logs. In 2026 they describe it
as an "agentic SIEM powered by native XDR."

**The genuinely distinctive asset is the Zero Day Initiative.** ZDI is the largest
bug bounty programme in the world, and it feeds vulnerability intelligence into the
product **ahead of vendor patches** — Trend claims up to three months of virtual
patching lead time. No other vendor here has an equivalent structural pipeline from
original vulnerability discovery to shipped protection.

---

### Fortinet — security in silicon

The one architecture on this list whose differentiator is hardware.

**Mechanism.** Fortinet builds **custom ASICs** — NP (network processor) and CP
(content processor) — into FortiGate appliances. These offload signature matching
and flow inspection off the general CPU, which is what lets deep inspection run at
multi-gigabit line rate. That is a real engineering moat: competitors doing the same
inspection in software pay a throughput penalty, and the penalty is worst precisely
when you turn on the expensive features (TLS inspection).

**FortiOS** is the common operating system across the estate, so policy is expressed
once rather than translated between products. **The Security Fabric** connects the
discrete products; **Fabric Stitches** are the automation primitive — pre-built
workflows that chain response across devices. The canonical example: FortiGate sees
a suspicious download → forwards to FortiSandbox → on a malicious verdict,
FortiSwitch quarantines the host at the port and FortiClient isolates the endpoint.
Note that this is *deterministic cross-device orchestration*, not ML.

**FortiGuard Labs** processes **100B+ security events daily** and pushes curated
feeds (AV, IPS, web filtering, DNS, sandboxing) to every Fabric device. FortiGuard's
character is automation at scale rather than deep human analysis.

---

### Check Point — one shared brain, prevention-first

**Mechanism.** The Infinity platform unifies four pillars under **one shared threat
intelligence brain**: **Quantum** (network/NGFW), **CloudGuard** (cloud, code to
runtime), **Harmony** (workspace — endpoint, mobile, email, browser, SaaS), and
**Infinity Core Services** (unified ops, AI, managed services).

**ThreatCloud AI** is that shared brain: **50+ distinct engines** feeding a
correlation layer that converts observed telemetry into IoCs pushed back to every
enforcement point. Check Point's cultural identity is **prevention-first** rather
than detect-and-respond — block it at the gateway before it lands, rather than
record it and reconstruct afterwards. They claim >3 billion attacks prevented
annually and a 99.8% block rate (vendor claims, from vendor-adjacent sources — treat
with caution).

---

### Cisco — push security into the infrastructure itself

**Mechanism.** Cisco's thesis is that they already own the switches, routers, and
servers, so security should be *distributed into that fabric* rather than bolted on
as an overlay.

**Hypershield** is the concrete expression: a distributed security fabric of
AI-based software and virtual enforcement points intended to be baked into core
networking hardware, with the ability to detect and block exploitation of *unknown*
vulnerabilities inside runtime workload environments. If it works as described, it
is enforcement at every hop rather than at a chokepoint.

**Splunk** (acquired) is the data layer, and the 2026 work is the integration:
Cisco XDR alerts and detections now feed **Splunk Enterprise Security**, joined by
telemetry from Cisco AI Defense, Multicloud Defense, and Talos. **Cisco XDR** acts
as the investigation and visualisation surface with "Instant Attack Verification."
**Duo** supplies the identity plane. **Talos** is the intelligence engine — one of
the largest commercial research teams, spanning researchers, analysts, IR, hunters,
and engineers, with output wired directly into product detection.

The honest read: Cisco's strategy is coherent but its execution risk is integration
debt across a very large acquired portfolio.

---

### Zscaler — the inline proxy as the whole architecture

**Mechanism.** The Zero Trust Exchange sits **inline between every user and every
destination**. Users connect to the nearest Service Edge, policy is applied, traffic
is forwarded. Critically it is a **proxy that terminates every connection**, which
is what makes **full TLS/SSL inspection at scale** possible — decrypt, inspect for
threat and data loss, re-encrypt, all inline.

That termination is the architectural crux. Hardware appliances choke on TLS
decryption because it is CPU-brutal; a horizontally scaled cloud of proxies does not
have that ceiling. Scale: **160+ data centres**, **500B+ transactions daily**.

**The zero-trust part is the connection model:** one-to-one connections brokered
between a user and a *specific application*, based on identity and context. The user
is never placed on the corporate network, so there is no network to move laterally
across. That is an architectural elimination of a threat class rather than a
detection of it — the strongest idea on this page.

**What it cannot see:** anything that does not traverse the proxy. Local process
behaviour is outside its telemetry entirely.

---

### Netskope — same shape as Zscaler, different centre of gravity

**Mechanism.** Netskope One converges SWG, CASB, ZTNA, DLP, FWaaS and digital
experience monitoring into a **single-pass inspection engine**: decrypt once, run
all security checks **in parallel**, re-encrypt once. Contrast with chained
inspection where each engine re-parses — single-pass is a latency argument and a
correctness argument at the same time.

**NewEdge** is the private backbone: 75+ regions, 120+ data centres, **full compute
at every PoP**. They are pointed about this — some competitors deploy partial nodes
that only do DNS resolution or traffic forwarding, while every NewEdge PoP runs the
complete stack. They also carry 300+ network adjacencies with direct Microsoft and
Google peering at every DC, which is a performance play: get onto the SaaS
provider's network as fast as possible.

**Netskope's real specialisation is SaaS/data context.** They combine **inline CASB**
(real-time enforcement on cloud app traffic) with **API-based CASB** (retrospective
inspection of data already at rest in SaaS tenants). The inline/API distinction
matters: API-only CASB can only tell you about a data exposure after it happened.
Their heritage is understanding cloud application semantics — not just "traffic to
Salesforce" but which action, which object, which user.

---

## 3. How they actually operate

### Detection content is a manufacturing pipeline, not a research output

The consistent pattern across all ten: a named research organisation (Unit 42,
Talos, FortiGuard Labs, ZDI, Counter Adversary Operations, ThreatCloud) whose output
is **wired into product engineering as a delivery requirement**, not published as
papers. Job descriptions for these teams explicitly include communicating with
product engineering to improve detection efficacy. The public blog posts are
recruitment and marketing; the actual product is the detection content shipped
silently on the back of the same investigation.

Two distinct styles are visible. **Automation-at-scale** (FortiGuard: 100B events
daily, push signatures to the fabric) versus **deep human analysis** (Unit 42, Talos:
incident response engagements feed named-adversary tradecraft back into detections).
Most of the big vendors now run both.

### The MDR flywheel is the real business model

EDR/XDR is technology; **MDR is the service that operates it**. The commercial
insight vendors act on is blunt: *a mid-size firm without analysts to operate EDR
around the clock owns detection it cannot use.* So every vendor here sells the
managed service on top — Falcon Complete, Trend Service One, Sophos MDR, and so on.

This creates a flywheel that is easy to miss: the MDR analysts see real incidents
across the whole customer base, and what they learn becomes product detection
content, which makes the product better, which sells more MDR. Vendors without a
managed service arm lose that loop.

**Land and expand** is uniform: start at endpoint or network, expand to identity,
cloud, data, and then the managed service. Palo Alto's "platformization" is the most
aggressive version — displace multiple point products at once, occasionally
absorbing the incumbent's remaining contract cost to do it.

### 2026: everyone pivoted to agentic, at the same time

Charlotte AI (CrowdStrike), Purple AI (SentinelOne), Cortex AgentiX (Palo Alto),
Security Copilot (Microsoft), agentic SIEM (Trend). The shared claim is autonomous
multi-step investigation: plan the investigation, gather evidence across the stack,
document a verdict the way a trained analyst would. Reported effect where numbers
exist: ~52% of cases resolved end-to-end with no human, averaging 89 seconds from
alert to response (vendor-sourced).

Read this structurally rather than as hype. The industry spent a decade solving
*collection* and thereby created an alert volume no human staff level can process.
Agentic triage is the forced consequence of winning the collection problem. It is
also why ecosystem-native agents are winning over standalone AI SOC tools — the
agent needs the platform's unified data model to reason over, which is exactly what
CrowdStrike's Enterprise Graph and Palo Alto's XDL exist to provide.

### The MITRE evaluation landscape changed too

ATT&CK Evaluations Enterprise 2026 **eliminated the split between "Enterprise" and
"Managed Services" rounds** — EDR, XDR, MDR, MSSP, SIEM and AI SOC vendors are now
evaluated on the same adversary scenarios with the same metrics, and must declare
product category tags so buyers know what was actually tested. Note also that some
vendors have withdrawn from participation, which is itself informative when reading
comparative claims.

---

## 4. What this means for Valkyrie

Four conclusions worth acting on.

**1. Valkyrie's architecture is the SentinelOne shape, and that is the correct one.**
Every other vendor's verdict lives in a cloud, a proxy, or a data lake. Valkyrie
cannot use any of those, because a privacy product that ships endpoint telemetry to a
vendor cloud is self-refuting. SentinelOne is the existence proof that a full
detection stack — reputation, static, behavioural, correlation, response — can run
entirely on-agent with the console outside the critical path. That is the reference
architecture to study, not Falcon's.

**2. Storyline is the borrowable idea, and Valkyrie is closest to it already.**
Tagging every process/file/registry/network event with a correlation ID so the attack
chain assembles itself, on-agent, is precisely what `nyx_graph.py` and the causality
graph work are reaching toward. This is the highest-value substrate to strengthen and
it does not require cloud scale to work.

**3. The structural gap is honest and unclosable, and should be stated rather than
papered over.** CrowdStrike correlates 2.5 trillion events per week; Palo Alto runs
2,900+ ML models over triple-density telemetry; Trend has ZDI feeding pre-patch
intelligence. None of that is reachable, and none of it is reachable by trying
harder. What is reachable is the class of detection that does not need cross-customer
scale: generalizing behavioural rules over local causality. That is already the
chosen path — this research confirms it rather than changing it.

**4. There is a positioning insight sitting in plain sight.** Every one of these ten
platforms is, mechanically, a telemetry-exfiltration business. CrowdStrike's product
*is* the pipe to their cloud. Zscaler's product *is* terminating and reading your
TLS. Microsoft's advantage *is* that they already have all your data. The thing none
of them can offer — because their architecture forbids it — is detection that never
leaves the machine. That is not a consolation prize for lacking scale; it is the one
axis on which the incumbents structurally cannot compete.

One caution against over-borrowing: Zscaler's strongest idea (eliminate lateral
movement by never putting the user on a network) and Fortinet's (put inspection in
silicon) are both unavailable at Valkyrie's layer. Study the ones that transfer —
on-agent autonomy, event-chain correlation IDs, evidence-constructed rather than
template-selected response — and skip the ones that require owning infrastructure.

---

## Sources

[CrowdStrike: Architecture of Agentic Defense](https://www.crowdstrike.com/en-us/blog/architecture-of-agentic-defense-inside-the-falcon-platform/) ·
[CrowdStrike Falcon platform](https://www.crowdstrike.com/en-us/platform/) ·
[Falcon sensor + cloud verdict analysis](https://ai.techclick.in/blog_crowdstrike_falcon_architecture) ·
[Palo Alto: What is Cortex XSIAM](https://www.paloaltonetworks.com/cyberpedia/what-is-extended-security-intelligence-and-automation-management-xsiam) ·
[Cortex XSIAM architecture docs](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/learn-about-cortex-xsiam/get-started-cortex-xsiam/cortex-xsiam-architecture) ·
[Unit 42 Threat Intelligence](https://www.paloaltonetworks.com/blog/2026/08/introducing-unit-42-threat-intelligence-know-what-matters-understand-the-adversary-and-act-faster/) ·
[Microsoft Defender XDR + Security Copilot](https://learn.microsoft.com/en-us/defender-xdr/security-copilot-in-microsoft-365-defender) ·
[Microsoft agentic security strategy 2026](https://siliconangle.com/2026/03/22/microsoft-outlines-agentic-ai-security-strategy-new-defender-entra-purview-capabilities/) ·
[SentinelOne Singularity architecture](https://ai.techclick.in/blog_sentinelone_architecture_agent_deployment) ·
[SentinelOne Static + Behavioral AI engines](https://ai.techclick.in/blog_sentinelone_static_behavioral_ai) ·
[Fortinet Security Fabric (FortiOS docs)](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/286973/fortinet-security-fabric) ·
[FortiOS as Fabric foundation](https://www.fortinet.com/content/dam/fortinet/assets/solution-guides/sb-fortios-security-fabric.pdf) ·
[Zscaler Zero Trust Exchange](https://www.zscaler.com/products-and-solutions/zero-trust-exchange-zte) ·
[Zscaler TLS/SSL inspection reference architecture](https://www.zscaler.com/resources/reference-architectures/tls-ssl-inspection-zscaler-internet-access.pdf) ·
[Check Point Infinity platform](https://www.thetechbag.com/checkpoint/checkpoint-infinity-platform) ·
[Check Point ThreatCloud AI](https://www.checkfirewalls.com/infinity-threatcloud-ai.asp) ·
[Cisco Hypershield](https://blogs.cisco.com/security/cisco-hypershield-a-new-era-of-distributed-ai-native-security) ·
[Cisco XDR + Splunk ES integration](https://blogs.cisco.com/security/emea-soc-2026) ·
[Cisco Talos](https://www.cisco.com/site/us/en/products/security/talos/index.html) ·
[Netskope NewEdge](https://www.netskope.com/blog/newedge-is-a-sase-ready-infrastructure-that-is-second-to-none) ·
[Netskope One SSE](https://www.netskope.com/products/security-service-edge) ·
[Trend Vision One platform](https://www.trendmicro.com/en_us/business/products/one-platform.html) ·
[Trend Vision One Security Operations](https://www.trendmicro.com/en_us/business/products/security-operations.html) ·
[Agentic SOC platform comparison 2026](https://d3security.com/blog/best-agentic-soc-platforms/) ·
[MDR vs EDR operating model](https://www.acronis.com/en/blog/posts/managed-edr-xdr-services/) ·
[MITRE ATT&CK Evaluations](https://evals.mitre.org/enterprise/er8/) ·
[Vendor revenue/ARR rankings 2026](https://cybersecuritytechcompanies.com/by-revenue)
