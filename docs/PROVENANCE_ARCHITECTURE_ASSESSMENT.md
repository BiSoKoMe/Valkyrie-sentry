# Valkyrie Provenance-Driven Architecture Assessment

**Phase 0 — Architecture Audit.**
This document is an honest, code-grounded assessment of whether Valkyrie can become a local, continuous, provenance-driven security and privacy enforcement layer, and what would have to change to prove it.

**Status of claims in this document:** every statement is tied to a specific file or test in the repository. Nothing is marketing language. Limitations are stated explicitly.

**Implementation update — provenance MVP:** Nyx observations now enter the EDR
through normalized, metadata-only `TelemetryEvent(category="privacy")` events;
the graph deduplicates retries by event id. The experimental consequence rule
raises an incident only after its mature-baseline and provenance-completeness
guards pass. Its default DNS response is a policy- and authority-gated
**dry-run** playbook, not a direct intelligence-memory mutation. Focused
structural/integration coverage is in `tests/test_privacy_consequence.py`.
This is not live efficacy, latency, or Atomic Red Team evidence.

**Phase ledger:** [`PROVENANCE_PHASE_STATUS.md`](PROVENANCE_PHASE_STATUS.md)
records the evidence status of phases 0–6. The code-local phases are complete
for this narrow experiment; phase 6 remains **LIVE VALIDATION BLOCKED** until a
snapshot-capable isolated Windows VM is provisioned.

**Browser-context update:** `browser_extension/` and
`valkyrie/browser_context.py` now provide an experimental Chromium native-
messaging path for metadata-only navigation, trusted gesture, form-submit, and
coarse consent signals. The bridge never stores page content, full URLs,
queries, form values, cookies, keystrokes, or DOM snapshots. It has no
authoritative Windows PID link and remains observation-only. See
[`BROWSER_CONTEXT_BRIDGE.md`](BROWSER_CONTEXT_BRIDGE.md).

---

## 1. Executive summary

Valkyrie is *not* starting from zero. It already has the seeds of the target architecture: a normalized event schema, an event bus, a real causality graph with process ancestry and artifact attribution, a multi-stage kill-chain correlator, a privacy data-guard (Nyx), a decision policy, and a small set of response actions. The central research question is therefore narrower than "can we build this?" It is:

> Can the existing causality graph be turned from an *explanation* primitive into a *decision* primitive, fed by both security and privacy observations, and drive enforcement at the earliest technically reachable point on Windows without sending private content off-box?

The honest answer today is: **partially implemented, partially feasible, partially blocked by Windows.** The graph and correlation engine exist and are tested. Real-time enforcement exists only at the DNS sinkhole. Cross-layer causality (browser → process → network → file) is fragmentary. Nyx now has an experimental, metadata-only normalized feed into the EDR, but browser semantic context and most cross-layer links remain absent. A real kernel driver exists as source but is not signed, loaded, or CI-tested.

The strongest potential point of differentiation is the **unified local provenance graph that reasons over both security and privacy consequences** — if it can be made to drive enforcement and if its limitations are measured rather than hidden.

---

## 2. Current architecture discovered in the repository

### 2.1 Pipeline

```
Sensors (process / network / persistence / ETW / optional kernel)
                    │
                    ▼
           TelemetryEvent (valkyrie/telemetry.py)
                    │
                    ▼
           EventBus / direct ingest → EdrEngine
                    │
                    ▼
    CausalityGraph (valkyrie/edr/causality.py)
                    │
                    ▼
    Detection → Incident → KillChainCorrelator / SequenceEngine
                    │
                    ▼
            Decision (valkyrie/decision.py)
                    │
                    ▼
    Response: block_domain / kill_process / isolate_host / remove_persistence
```

DNS has a parallel, real-time path:

```
OS DNS client ──► DNSInterceptor (valkyrie/dns_interceptor.py)
                    │
                    ▼
        Store.log ──► Store bus ──► EDR + dashboard
                    │
                    ▼
        block / allow / deceive (decided inline, enforced inline)
```

### 2.2 Components that already exist and are real

| Component | File | Status | Notes |
|-----------|------|--------|-------|
| Normalized event schema | `valkyrie/telemetry.py` | **Shipped** | `TelemetryEvent` with categories DNS/process/network/persistence/malware/asset/privacy. Unit-tested round-trip. |
| Event bus | `valkyrie/eventbus.py` | **Shipped** | Thread-safe, type-filtered, exception-isolating pub/sub. Used by Store and EDR. |
| Causality graph | `valkyrie/edr/causality.py` | **Shipped** | Process ancestry keyed on `(pid, create_time)`, PID-reuse guard, terminator list, CGO query, artifact attribution. Honest about inferred nodes and evicted state. 683 lines, 80 test checks. |
| Kill-chain correlator | `valkyrie/edr/killchain.py` | **Shipped** | Distinct ATT&CK tactics per process chain, lineage-quality and temporal-quality factors. 516 lines, 51 test checks. |
| Causal detection | `valkyrie/edr/causal_detect.py` | **Experimental** | Tries to originate detections from graph structure + per-host baseline. Guarded by baseline maturity (300 observations / 3 sessions), motif+rarity requirement, trusted-lineage discount, and completeness cap. Tested only on synthetic subgraphs. |
| EDR engine | `valkyrie/edr/engine.py` | **Shipped** | Ingests telemetry, records causality, creates incidents, runs plugins, correlates chains/sequences, publishes to bus. 1,101 lines. |
| Decision policy | `valkyrie/decision.py` | **Shipped** | Deterministic signal → action mapping with profiles (standard/high-risk/travel/clean-room). 10 pytest functions. |
| Response actions | `valkyrie/edr/response.py` | **Shipped** | `block_domain`, `unblock_domain`, `kill_process`, `isolate_host`, `release_isolation`, `remove_persistence`, `restore_persistence`. Dry-run by default; safety layers in `invariants.py`, `reversibility.py`, `leases.py`, `cascade.py`. |
| Process telemetry | `valkyrie/process_telemetry.py` | **Shipped** | Userland `psutil` poller, 2 s default interval. Classifies LOLBins, Office-spawns-shell, suspicious paths, command-line heuristics, discovery commands. 49 test checks. |
| Network telemetry | `valkyrie/network_telemetry.py` | **Shipped** | Userland `psutil.net_connections` poller, 3 s default interval. Flags threat-intel IPs and connection anomalies. 18 test checks. |
| Persistence telemetry | `valkyrie/persistence_telemetry.py` | **Shipped** | Polls ASEPs (Run keys, services, scheduled tasks, startup folders, WMI). |
| ETW sensors | `valkyrie/etw/{powershell,wmi,sysmon,native_process,wineventlog}.py` | **Shipped** | PowerShell 4104, WMI 5861, Sysmon EID 1/3/7/8/10/13, native process creation from ETW. Managed by `SensorManager` with dedup/backpressure/watchdog. 34 pytest functions. |
| Kernel bridge + driver source | `valkyrie/kernel_bridge.py`, `driver/valkyrie_km/` | **Buildable, not deployed** | Real WDK source (1020 lines) implementing process create/exit, image load, remote thread, registry autostart, LSASS access block, agent self-protect, and process-launch prevention. Compiled `.sys` exists locally but is **not signed** and has **never been loaded** in CI or live runs. |
| DNS interceptor | `valkyrie/dns_interceptor.py` | **Shipped** | UDP sinkhole on port 5353/5300. Real-time block/allow/deceive. Process attribution via `ProcessWatcher`. Threat-intel, learned memory, scanner, anomaly, CNAME uncloaking, answer-IP screening. 843 lines. |
| Firewall | `valkyrie/firewall.py` | **Shipped** | `netsh advfirewall` for DoH IP rules on Windows; in-process CIDR set for lookup; Linux iptables-restore for full CIDR. On Windows, only DoH ranges get kernel rules; other ranges are checked after DNS resolution. |
| Nyx privacy guard + EDR feed | `valkyrie/nyx.py`, `valkyrie/tls_addon.py` | **Experimental integration** | Observes outbound HTTP requests for personal-data leaks, masks samples, can rewrite with fake persona data. It emits only category/destination/first-party metadata to EDR; body and masked sample are excluded from the graph. |
| Browser context bridge | `browser_extension/`, `valkyrie/browser_context.py` | **Experimental integration** | Chromium extension → native host → loopback API. Emits only interaction metadata and sanitized origin; not process-attributed or an enforcement point. Fails closed when its token ACL cannot be verified. |
| Nyx tracker graph | `valkyrie/nyx_graph.py` | **Shipped** | Correlates tracker sightings across first-party sites locally. 19 test checks. |
| Behavioral rules / anomaly | `valkyrie/behavioral_rules.py`, `valkyrie/behavior_score.py`, `valkyrie/network_score.py` | **Shipped** | List-free classifiers and per-host baselines. |
| Evaluation harness | `redteam/evaluation/`, `tests/harness.py`, `tools/efficacy.py` | **Shipped** | Tier A (classifier replay), Tier B (live Atomic Red Team on disposable VM), evasion harness, reversibility tests. Live-fire report: 55/73 in-scope techniques detected (75.3%) across 26 CI runs. |

### 2.3 Honest boundaries already documented in the code

The repository is unusually self-critical. Key documented limits:

- Process telemetry is a **userland poller**; short-lived processes can be missed (`process_telemetry.py:9-13`).
- Causality graph completeness is limited by sensor completeness; inferred nodes are flagged (`edr/causality.py:46-72`).
- Kill-chain correlator raises no new primary signals (`edr/killchain.py:33-35`).
- Causal detection is the most false-positive-prone component and is heavily guarded (`edr/causal_detect.py:15-61`).
- Kernel driver is off by default; without it, pre-execution blocking is unavailable (`kernel_bridge.py:13-14`, `driver/README.md:17`).
- TLS inspection cannot inspect certificate-pinning apps (`README.md:27`).
- Response actions are dry-run by default (`edr/response.py:3-8`).

---

## 3. Windows data-source reality

For each proposed sensor we document what it can observe, what it cannot, privilege/driver requirements, privacy concerns, performance concerns, practical status, and real-time enforcement capability.

| # | Source | What it can observe | What it cannot observe | User-mode? | Driver? | MS signing? | Privacy concern | Performance concern | Practical status | Real-time enforcement? |
|---|--------|---------------------|------------------------|------------|---------|-------------|-----------------|---------------------|------------------|----------------------|
| 1 | Process creation/termination | `psutil` polling: pid, ppid, name, path, cmdline, create_time (racy, ~2 s latency). ETW/Kernel: authoritative, near-real-time. | `psutil`: processes that start+exit between polls; accurate parent if parent exited first; limited path/cmdline across sessions without elevation. ETW: still needs elevation for some channels. | `psutil`: yes. ETW: admin for many providers. | Kernel callbacks give authoritative lineage. | Driver signing required for kernel callbacks. | Low: metadata only. | `psutil`: low. ETW: moderate event volume. | `psutil`: shipped. ETW native process sensor: shipped. Kernel driver: source exists, unsigned. | `psutil`: no. ETW: observe only. Kernel driver: **yes** — can deny process creation if signed+loaded. |
| 2 | Process ancestry | `CausalityGraph` walks ppid edges + terminators. Kernel gives exact ppid at create time. | Cannot see ancestry above Valkyrie start time; misses processes that exited before first poll; PIDs can be reused (mitigated by create_time). | Partially. | Authoritative ancestry needs kernel. | Yes for kernel. | Low: metadata only. | Graph bounded to 8,192 nodes; artifact cap 200/node. | Shipped with documented limits. | No. |
| 3 | Thread activity | ETW/Kernel can see remote-thread creation; kernel can block. | Cannot see benign intra-process threads semantically; injection ≠ malicious. | ETW: admin. | For blocking: yes. | Yes. | Low: metadata only. | Moderate. | ETW sensor shipped; kernel source exists. | Kernel driver can block remote-thread creation if signed+loaded. |
| 4 | ETW | Process creation, PowerShell script-block (4104), WMI activity, network connections, file activity, registry (providers vary). | Requires provider registration; some channels need admin; event volume can be high; no pre-operation blocking. | Admin for many useful providers. | No. | No. | Low if collecting metadata; PowerShell 4104 can contain scripts (handled as security telemetry, not user content). | High event volume possible. | Shipped for PowerShell, WMI, Sysmon passthrough, native process. | **No** — ETW is observe-only. |
| 5 | Sysmon | Process creation (EID 1), network (EID 3), image load (EID 7), remote thread (EID 8), file (EID 11), registry (EID 13/14). | Requires Sysmon installed + configured; not real-time blocking; can be tampered if no driver protection. | Install + config. | Sysmon driver is Microsoft-signed; Valkyrie does not install its own. | N/A for Valkyrie (uses existing Sysmon). | Configurable via Sysmon config; Valkyrie does not set it. | High event volume. | Sysmon sensor shipped; Sysmon setup is opt-out. | **No** — Sysmon is observe-only. |
| 6 | Windows Filtering Platform (WFP) | Network packets, connection attempts, app-level filtering. | Complex COM/C API; user-mode callouts can inspect but not block at full line rate without driver. | User-mode callouts possible. | For kernel callouts: yes. | Yes for driver. | Low: connection 5-tuple, not payload. | Can add latency per packet. | **Not implemented** in Valkyrie except via `netsh advfirewall`. | Could be implemented for network block at connect time; currently DNS sinkhole is the real-time network control. |
| 7 | Network connection metadata | `psutil.net_connections`: pid, local/remote ip/port, status. ETW network provider: similar with timestamps. | Racy; short-lived connections missed; UDP stateless; cannot see payload. | `psutil`: yes (limited by session). ETW: admin. | For full packet inspection: yes. | For driver: yes. | Low: 5-tuple metadata. | Low for polling; high for ETW. | `psutil` collector shipped; ETW network provider not implemented. | **No** — observe-only. |
| 8 | DNS | DNSInterceptor sees every DNS query, qname, qtype, source IP/port, mapped process. | Encrypted DNS (DoH/DoT/DoQ) bypasses unless blocked/inspected; can be tunneled. | Yes (binds local port, admin to redirect OS DNS). | No. | No. | Low: query name + process metadata; query contents are hostnames, not page content. | Low per-query; process attribution adds small latency. | **Shipped and real-time.** | **Yes** — NXDOMAIN/sinkhole returned inline. |
| 9 | File activity | Kernel minifilter: create/read/write/delete, path, pid. Sysmon EID 11: file create. Ransomware shield uses canary files + entropy. | Userland cannot reliably observe all file I/O in real time; path normalization and handle semantics are tricky. | No for kernel. | Minifilter: yes. | Yes. | Medium: file paths can be sensitive; content not read by current code. | High event volume; minifilters must be careful not to deadlock. | Ransomware shield: shipped. General file causality: **not implemented**. | Minifilter could block pre-write if signed+loaded. |
| 10 | Registry activity | Kernel callback (CmRegisterCallbackEx): pre/post set, key path, pid. ETW/WMI/registry poller. | Userland polling misses short-lived changes; requires elevation. | Partially. | For reliable real-time: yes. | Yes. | Low: key path, not value content. | Moderate. | Persistence telemetry polls ASEPs. Kernel source exists but not deployed. | Kernel callback can block pre-set if signed+loaded; current driver is detection-only for registry. |
| 11 | Services | SCM API / `sc` / WMI. | Cannot see service creation in real time without kernel callback or ETW. | Yes (admin). | No. | No. | Low. | Low. | Persistence telemetry shipped. | No. |
| 12 | Scheduled tasks | Task Scheduler 2.0 API, WMI events, XML parsing. | Some tasks hidden; needs admin for system tasks. | Yes (admin). | No. | No. | Low. | Low. | Persistence telemetry shipped. | No. |
| 13 | Persistence mechanisms | Run keys, RunOnce, startup folders, services, scheduled tasks, WMI subscriptions. | Kernel-level rootkits; some ASEPs require admin to read. | Yes (admin). | No (except registry kernel callback). | No. | Low. | Low. | Shipped. | No. |
| 14 | Browser/application context | TLS inspector (`tls_inspector.py` + `tls_addon.py`) sees cleartext HTTP if TLS inspection enabled; Nyx parses request bodies for PII leaks. | Cannot see browser-internal events (clicks, tabs, consent dialogs, JS execution) without browser extension/native messaging; pinned-cert apps bypass TLS inspection. | TLS inspection: requires local CA + admin; browser extension: yes (user install). | No. | No. | High if reading bodies; Nyx masks samples and bounds scan to 16 KB. | Moderate: TLS proxy adds latency; body scanning bounded. | TLS inspector shipped (opt-in). Browser extension: **not implemented**. | Nyx can rewrite request bodies inline (act mode). Browser semantic events cannot be enforced without extension. |
| 15 | Application APIs | Valkyrie exposes local FastAPI; apps could call it. | No standard OS API for "what is the browser doing?" | Yes. | No. | No. | Depends on API. | Low. | **Not implemented** for browser. | No. |
| 16 | Browser extensions / native messaging | Could report URL, tab, frame, user gesture, consent state. | Requires per-browser extension install; store policy; extension can be disabled. | Yes. | No. | No. | Medium: URL can be sensitive; must avoid full page content. | Low. | **Not implemented**. | Could request block/allow via native messaging, but enforcement still relies on OS network controls. |
| 17 | IPC | Windows has many IPC mechanisms; most are not centrally observable. | No unified IPC audit trail. | Partially (some APIs). | For some: yes. | Yes. | Low–medium. | Low. | **Not implemented**. | No. |
| 18 | Authentication/session context | Token query, logon session, LSA. | LSASS protection requires anti-malware entitlement. | Partially (admin). | For blocking: yes + entitlement. | Yes + ELAM entitlement for blocking. | High: credential material must never be read. | Low. | **Not implemented**. | Driver can strip LSASS access rights if signed+entitled. |
| 19 | Security boundaries | Integrity level, sandbox, UAC, session, session 0. | Hard to observe consistently from user mode. | Partially. | For authoritative: yes. | Yes. | Low. | Low. | **Not implemented** as graph attributes. | No. |
| 20 | Kernel callbacks / minifilters / drivers | PsSetCreateProcessNotifyRoutineEx, PsSetLoadImageNotifyRoutine, PsSetCreateThreadNotifyRoutine, CmRegisterCallbackEx, ObRegisterCallbacks, minifilter. | Requires signed driver; some callbacks require anti-malware entitlement; high engineering cost; kernel bugs = BSOD. | No. | Yes. | Yes + entitlement for some. | Low for callbacks; payload inspection would be high. | High engineering + stability risk. | Source exists; not built/signed/loaded in CI. | Yes, if signed and loaded. |

---

## 4. Proposed architecture

The target is the layered pipeline from the mission statement. Mapped to real implementation mechanisms:

```
USER / APPLICATIONS
        │
        ├── Browser extension / native messaging (NOT IMPLEMENTED)
        ├── Application APIs (TLS inspector — shipped, opt-in)
        └── Windows shell / processes
        │
        ▼
┌─────────────────┬─────────────────┬─────────────────┐
│  Application    │  Windows        │  Network        │
│  observation    │  telemetry      │  observation    │
│  (TLS proxy,    │  (ETW, Sysmon,  │  (DNS sinkhole, │
│   browser ext)  │   kernel driver, │   psutil, WFP)  │
│                 │   psutil)       │                 │
└─────────────────┴─────────────────┴─────────────────┘
        │
        ▼
LOCAL EVENT FABRIC (EventBus + SensorManager)
        │
        ▼
NORMALIZATION LAYER (TelemetryEvent schema)
        │
        ▼
CONTEXT / PROVENANCE ENGINE (CausalityGraph)
        │
        ▼
CAUSALITY GRAPH + per-host baseline (CausalBaseline)
        │
        ▼
BEHAVIOR ENGINE (behavioral rules, anomaly, sequences, kill-chain)
        │
        ├───────────────┐
        ▼               ▼
SECURITY CONTEXT   PRIVACY CONTEXT
(Nyx + EDR labels)  (Nyx observations)
        │               │
        └───────┬───────┘
                ▼
      CONSEQUENCE ENGINE ("what did this cause?")
                │
                ▼
      POLICY ENGINE (decision.py + playbooks)
                │
          ┌─────┴─────┐
          ▼           ▼
        ALLOW       BLOCK / DECEIVE / CONTAIN
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
       DNS        Process    Network
       sinkhole   kill       isolate
                  (driver    (netsh/WFP)
                   block
                   if signed)
```

Key difference from current state: **Nyx observations become first-class artifacts in the causality graph**, and the graph is consulted for consequence-based policy decisions, not only for incident explanation.

---

## 5. Gap analysis: existing vs. missing

### 5.1 Existing and reusable

1. `TelemetryEvent` schema — covers all needed categories.
2. `EventBus` — can carry both security and privacy events.
3. `CausalityGraph` — the core provenance primitive; already supports artifact attribution.
4. `KillChainCorrelator` — multi-tactic correlation across process lineage.
5. `CausalDetect` / `CausalBaseline` — per-host normalcy learning from structure.
6. `EdrEngine` — the single ingest and correlation point.
7. `decision.py` — graded policy with profiles.
8. Response actions — block domain, kill process, isolate host, remove persistence.
9. DNS interceptor — real-time enforcement at the earliest network point.
10. Nyx — observes and can act on privacy leaks.

### 5.2 Missing

| Gap | Why it matters | Feasibility |
|-----|----------------|-------------|
| Nyx → EDR/causality feed | Implemented experimentally as normalized, metadata-only privacy telemetry. It still lacks live-efficacy/latency evidence and browser semantic attribution. | Implemented; must be measured on a disposable VM. |
| Browser semantic context | Experimental user-mode bridge now distinguishes browser-trusted gesture/form/consent metadata from background navigation and preserves origin only. It still cannot determine consent validity, inspect page semantics, or join context to a Windows PID. | Implemented as an observation experiment; requires extension/native-host installation and live validation. |
| File-activity causality | File writes/reads are not attributed to process chains except ransomware canaries. | Medium–high — needs kernel minifilter or Sysmon EID 11 integration. |
| Real-time process blocking | Without signed driver, cannot prevent process launch. | Low until driver is signed; high engineering cost. |
| Real-time network blocking (non-DNS) | On Windows only DoH IPs get kernel firewall rules; other IPs are checked after DNS answer. | Medium — WFP user-mode callout or more netsh rules. |
| Consequence engine driving policy | Experimental `consequence.py` records a policy and authority-gated, dry-run future-DNS playbook. It is not an inline DNS query check and is not live validated. | Implemented as a guarded dry-run experiment. |
| Measured end-to-end latency | Synthetic local ingest p50/p95/p99 is measured, but observation→analysis→DNS-enforcement latency is not. | Partial; requires a controlled live workload and DNS hot-path instrumentation. |
| Signed kernel driver | Driver source exists but is not signed/loaded/tested. | Low — external dependency on EV cert + Microsoft attestation (+ ELAM entitlement for full LSASS blocking). |

### 5.3 Architectural conflicts

1. **Privacy vs. correlation:** Nyx intentionally does not store raw values. Feeding Nyx into the causality graph risks retaining more personal data. The current masked-sample design must be preserved; only the category/destination/first-party metadata should enter the graph.
2. **Latency vs. depth:** Consulting a growing causality graph on the DNS hot path could add milliseconds per query. Must measure before enabling.
3. **Real-time vs. correctness:** Process attribution from `psutil` is racy; using it for automatic kill decisions can hit the wrong process. The kernel driver closes this gap but is not deployed.
4. **Default dry-run vs. automatic enforcement:** The response system is safe by default, which is correct, but proving the "earliest enforceable point" requires opt-in automatic playbooks. This must be explicit and profile-aware.

---

## 6. Feasibility on Windows

### 6.1 Technically feasible without new drivers

- Normalize and correlate process, network, persistence, ETW, Sysmon, DNS, and Nyx events in one graph.
- Make consequence-based detections from structure (with baseline maturity guards).
- Drive DNS sinkhole decisions from graph context.
- Drive manual / playbook-based process kill and network isolation.
- Measure latencies.
- Add a browser extension for semantic context (user-mode only).

### 6.2 Requires browser/application integration

- Browser-initiated vs. script-initiated action distinction.
- Consent dialog observation.
- Per-tab first-party origin for Nyx (currently inferred from Referer/Origin headers, which is incomplete).
- DOM-level tracker detection.

### 6.3 Requires kernel drivers

- Pre-execution process blocking.
- Authoritative, real-time process creation/termination/lineage without polling gaps.
- Real-time file write/read attribution and blocking.
- Real-time registry write blocking.
- LSASS access blocking (also requires anti-malware entitlement).
- Full WFP kernel callout for arbitrary packet blocking.

### 6.4 Requires elevated privileges

- DNS interception on port 53.
- `netsh advfirewall` for DoH rules and host isolation.
- ETW channels that need admin.
- Sysmon installation/configuration.
- Process kill of protected/system processes.
- Loading any kernel driver.

### 6.5 Where real-time enforcement is possible

| Point | Current mechanism | Requires |
|-------|---------------------|----------|
| DNS query | DNSInterceptor sinkhole | Local DNS redirect + admin for port 53. |
| IP after DNS answer | In-process CIDR check + rewrite answer | Already works; not true packet block. |
| DoH bypass | `netsh` block on TCP/443 to known DoH IPs | Admin. |
| Process termination | `kill_process` responder via `psutil` | Admin for some processes; not pre-execution. |
| Host network isolation | `netsh advfirewall` policy change | Admin. |
| Persistence removal | Registry/file deletion via responders | Admin. |

### 6.6 Where real-time enforcement is impossible without new components

| Point | Why | What would be needed |
|-------|-----|----------------------|
| Pre-execution process block | No signed kernel driver loaded | Signed minifilter/ELAM driver + attestation. |
| Pre-write file/registry block | No kernel callback registered | Signed kernel driver with blocking callbacks. |
| Packet-level network block on Windows (non-DNS, non-DoH) | Only in-process IP lookup after DNS | WFP kernel callout or many netsh rules (latter not scalable per current code). |
| Browser semantic enforcement | No browser extension | Extension + native messaging + OS network enforcement underneath. |
| LSASS credential-theft block | No anti-malware entitlement | Driver + Microsoft ELAM entitlement. |

---

## 7. Strongest potential point of differentiation

A **local, unified provenance graph that reasons over both security and privacy consequences**:

- Existing EDRs keep privacy and security separate or rely on cloud aggregation.
- Existing privacy blockers do not build a causality graph and do not reason about "what did this cause?"
- If Valkyrie can show that a browser context → process → network → data-leak chain can be detected and acted on locally, faster and with fewer false positives than separate systems, that is a real architectural difference.

The evidence standard is strict: it must be measured, not claimed. The first experiment should ask: **does adding Nyx privacy artifacts to the security causality graph reduce false positives or increase true positives on a realistic scenario?**

---

## 8. Smallest MVP capable of proving differentiation

**Scenario:** A browser/document owner process spawns a child that makes a first-seen outbound network connection and/or leaks personal data to a third party. Valkyrie should detect the chain and block the network egress.

**MVP scope (narrow, measurable):**

1. **Feed Nyx observations into the causality graph.** Change `valkyrie/tls_addon.py` so that every Nyx observation also emits a `TelemetryEvent` to `EdrEngine.ingest_telemetry`, with `category="network"` or a new privacy category, `actor_pid` from `pid_for_local_port`, and artifact kind `nyx_leak` / `nyx_fake`.
2. **Attribute network connections to the causality graph.** Ensure `NetworkCollector` events are already attributed (they are not today in the graph; this may need a small wiring fix).
3. **Add ONE consequence rule.** In `valkyrie/edr/causal_detect.py` or a new `valkyrie/edr/consequence.py`: if the CGO of a process chain is a document/browser owner, a child process makes a first-seen DNS/network connection, and the same chain has a `nyx_leak` artifact, raise a detection.
4. **Drive enforcement at DNS time.** In `valkyrie/dns_interceptor.py` or via a playbook, when the process chain for the querying PID matches the consequence rule, return `blocked` instead of `allowed`.
5. **Measure.** Add instrumentation and tests for end-to-end latency, false positives on installers/updaters, and false negatives on synthetic chains.

**Why this is the smallest viable proof:** it tests the central hypothesis (unified reasoning over security + privacy provenance) using existing components, without requiring a signed driver or browser extension. It is falsifiable: if the rule does not improve detection or causes too many FPs, the hypothesis is disproven for this narrow case.

---

## 9. Exact files/modules that should be modified

### 9.1 For the MVP

| File | Change |
|------|--------|
| `valkyrie/tls_addon.py` | Emit a `TelemetryEvent` for every Nyx observation, feeding `edr_engine.ingest_telemetry` if available. Use category/destination/first-party metadata only; exclude body and masked sample. |
| `browser_extension/`, `valkyrie/browser_context.py` | Experimental browser extension, native host, loopback token boundary, and metadata-only browser-context collector. |
| `valkyrie/telemetry.py` | Add artifact kinds for Nyx: `nyx_leak`, `nyx_fake`, `page_clean`, `tracker_pixel`, `fingerprint`. Ensure privacy categories do not carry raw content. |
| `valkyrie/edr/causality.py` | Confirm `attribute()` accepts the new Nyx artifact kinds; add `nyx_*` to the `Artifact` kind vocabulary if needed. |
| `valkyrie/process_telemetry.py` / `valkyrie/etw/native_process.py` | Prefer ETW/native process events for graph seeding over `psutil` polling where available, to reduce attribution latency. |
| `valkyrie/network_telemetry.py` | Ensure `NetworkCollector` events reach `CausalityGraph.attribute()` with correct `actor_pid`. Currently they go to `ingest_telemetry` but may not be recorded as graph artifacts. Verify and fix. |
| `valkyrie/edr/causal_detect.py` or new `valkyrie/edr/consequence.py` | Add the consequence rule: browser/document CGO + child network + Nyx leak = detection. Keep the baseline maturity and trusted-lineage guards. |
| `valkyrie/decision.py` | Ensure a privacy-security crossover signal maps to `Action.BLOCK` in the appropriate profiles. |
| `valkyrie/edr/playbooks.py` | Add a default playbook (dry-run first, then enforce) for the consequence detection. |
| `valkyrie/dns_interceptor.py` | Optional: consult the causality graph for the querying PID before final allow decision. This is the real-time enforcement hook. |
| `valkyrie/__main__.py` | Wire the TLS addon to the EDR engine context so it can emit telemetry. |

### 9.2 Supporting instrumentation

| File | Change |
|------|--------|
| `valkyrie/edr/metrics.py` | Add end-to-end latency histogram: event ts → decision ts → enforcement ts. |
| `valkyrie/edr/engine.py` | Stamp latency fields on Detection/Incident. |
| `valkyrie/store.py` | Stamp DNS decision latency. |

---

## 10. Exact tests required

### 10.1 Unit tests

- `tests/test_cross_layer_provenance.py`
  - Synthetic process chain (browser owner → child → network connection) is correctly built.
  - Nyx leak artifact attaches to the right process node.
  - CGO query returns the browser owner for a deep chain.
- `tests/test_privacy_security_unification.py`
  - Nyx observation emitted as `TelemetryEvent` reaches `EdrEngine` and becomes a graph artifact.
  - Consequence rule fires only when browser CGO + network + Nyx leak coexist.
  - Consequence rule does NOT fire for routine installer/updater shapes.
- `tests/test_consequence_enforcement.py`
  - DNS interceptor returns `blocked` for a query whose process chain matches the consequence rule.
  - Dry-run mode logs the intended block without returning NXDOMAIN.
  - Non-matching queries are unaffected.

### 10.2 Integration tests

- `tests/test_nyx_edr_integration.py`
  - Start a minimal `AppContext` with DNS interceptor, EDR, Nyx, and TLS addon.
  - Inject a simulated HTTP request through Nyx and verify it reaches the EDR incident pipeline.

### 10.3 Regression tests

- Ensure Nyx does not regress: masked samples only, no raw content in graph or incidents.
- Ensure DNS latency does not regress: benchmark before/after adding causality lookup to hot path.
- Ensure causal detection baseline guards still suppress immature-baseline FPs.

### 10.4 Adversarial tests

- Rapid process creation/destruction to test attribution holes.
- Process name masquerade (e.g., `svchost.exe` in temp) to test terminator path-awareness.
- PID reuse to test node-key collision handling.
- Legitimate installer that produces the same shape (browser setup spawning helper → network) to test false-positive rate.
- Missing Nyx data (no Referer/Origin) to test the third-party gate.

### 10.5 Performance tests

- Event throughput: 1,000 synthetic events/min through the graph.
- DNS query latency: p50/p95/p99 with and without causality lookup.
- Memory growth: 24-hour simulation with process churn.

### 10.6 Implemented-test mapping (current MVP)

The names above were Phase 0 proposals. The implemented suite consolidates the
same checks where they exercise one live code path, avoiding duplicate mock
fixtures:

| Requirement | Implemented evidence | Status |
|---|---|---|
| Cross-layer chain, CGO, and privacy artifact | `tests/test_privacy_consequence.py`, `tests/test_causality.py` | Integration / structural |
| Nyx normalized telemetry and privacy-retention boundary | `tests/test_nyx.py`, `tests/test_privacy_consequence.py` | Integration |
| Ordering, PID reuse, missing lineage, duplicate and storm handling | `tests/test_provenance_adversarial.py` | Adversarial mechanism |
| Decision/authority-gated future DNS playbook | `tests/test_privacy_consequence.py`, `tests/test_playbooks.py` | Dry-run integration |
| Local ingest p50/p95/p99 and graph bound | `tools/provenance_benchmark.py`, `docs/PROVENANCE_EXPERIMENT_REPORT.md` | Synthetic mechanism measurement |
| Atomic/Tier-B live validation | Disposable VM required | **LIVE VALIDATION BLOCKED** |
| Browser bridge privacy/API boundary | `tests/test_browser_context.py` | Mechanism integration |

---

## 11. Biggest technical risks

1. **Attribution fragility.** Userland process attribution is racy. The kernel driver closes this but is not deployed. A wrong attribution can kill the wrong process or block the wrong DNS query.
2. **False-positive avalanche from causal detection.** Structure alone is not malicious. The existing guards are conservative, but adding Nyx + network to the graph may still produce installer/update FPs. Must be measured on real workloads.
3. **Latency in the DNS hot path.** Adding graph queries to `DNSInterceptor._handle` could add milliseconds. The mission requires measured latency, not claimed latency.
4. **Privacy boundary creep.** Feeding Nyx into the EDR risks retaining more user content. The design must keep only category/destination/first-party metadata in the graph; raw bodies stay in the TLS proxy and are discarded.
5. **Kernel driver not deployable.** Without a signed, attested driver (and ELAM entitlement for LSASS), pre-execution and pre-write blocking remain impossible. This is an external dependency, not a code problem.
6. **Browser semantic gap.** Without a browser extension, Valkyrie cannot reliably distinguish user-initiated from script-initiated actions. The MVP will be limited to network-level provenance.
7. **Sustained event volume.** The causality graph caps nodes and artifacts, but a high-event-storm scenario has not been load-tested end-to-end.
8. **Measurement gaps.** The repo does not currently measure end-to-end observation→enforcement latency. Claims about "real-time" must be grounded in new instrumentation.

---

## 12. Comparative research notes (preliminary)

This section is deliberately short because full comparative research belongs after the MVP exists.

- **Microsoft Defender / CrowdStrike / SentinelOne / Palo Alto Cortex:** All have cloud-backed, kernel-level EDR with provenance graphs. They differ from Valkyrie in two ways: (1) telemetry typically leaves the endpoint, and (2) privacy and security are separate products. Valkyrie's potential difference is **local-only unified reasoning**.
- **Browser security systems (e.g., Chrome Safe Browsing, Edge SmartScreen):** Use cloud blocklists and browser-internal signals. They do not build a cross-application causality graph.
- **Privacy blockers (uBlock Origin, DuckDuckGo, etc.):** Block by list or heuristic at the browser/network layer. They do not correlate with OS process provenance.
- **Host-based provenance systems (e.g., CamFlow, OPUS):** Academic systems with strong provenance but limited real-time enforcement and limited Windows applicability.
- **DLP systems:** Focus on content inspection and policy enforcement, often cloud-managed, not on causal chain reconstruction.

**Honest conclusion:** the *idea* of a local, unified, provenance-driven security+privacy layer is not yet common in commercial endpoint security. The *evidence* that Valkyrie achieves it does not yet exist. The MVP is the smallest step that can produce evidence.

---

## 13. Recommendation: what to do next

1. Complete isolated-VM validation for the existing Nyx/EDR consequence experiment and the new browser-context bridge.
2. Measure browser-event → normalized-event → decision latency and false positives on normal browsing and installers.
3. Build a defensible process-attribution join only after its error rate is measured; never guess a PID from browser context.
4. Keep automatic consequence enforcement gated until those measurements and rollback behavior are independently verified.
5. Pursue signed-driver/WFP work as a separate deployment and safety program, not as an unvalidated development-host change.

The architecture can become genuinely different, but only if it is built as a sequence of measured, falsifiable experiments rather than as a larger feature list.
