# Valkyrie — Everything It Does

A complete, **honest** inventory of what Valkyrie actually does — grounded in the
code, not marketing. Where a capability has a boundary (userland vs kernel,
local vs infra-scale), it says so plainly. Valkyrie is a **local-first, privacy-
first Windows security platform**: everything runs on the box, no cloud account,
no telemetry leaving the machine unless you explicitly turn on an export.

Architecture spine: **sensors → `TelemetryEvent` → EventBus → EdrEngine
(correlation) → Store / SIEM / UI**. Every subsystem plugs into that one spine —
one event bus, one store, one correlation engine, one API. See
`docs/ARCHITECTURE.md`.

---

## 1. DNS filtering, sinkhole & privacy resolution

- **Local recursive resolver** (`resolver.py`) — manages a local Unbound
  recursive DNS resolver so lookups don't depend on (or leak to) a third-party
  DNS provider.
- **DNS sinkhole / interceptor** (`dns_interceptor.py`) — the decision core.
  Every query runs an ordered pipeline: user rules → threat-intel IOC match →
  learned-intelligence fast path → site scanner → blocklist → behavioral
  classifier → baseline anomaly. Blocked names are sinkholed; the answer IP is
  also screened against the firewall/intel CIDR sets (catches hard-coded-IP and
  fast-flux cases DNS alone would miss).
- **Blocklists** (`blocklist.py`, `seed_blocklist.py`) — a curated built-in
  **seed blocklist** gives day-one protection with no download; external list
  downloads are strictly opt-in.
- **Behavioral DNS heuristics** (`behavioral.py`) — per-query scoring on
  subdomain Shannon entropy, per-process query-rate bursts, and an offline
  abuse-heavy-TLD reputation set. Precision-first (a false positive breaks a
  real site).
- **Site scanner** (`site_scanner.py`) — positive-signal tracker/ad detection
  (default allow; only blocks on confirmed tracker evidence) **plus DGA C2
  detection** (see §7).
- **DoH-bypass detection** (`doh_detector.py`) — flags processes tunneling DNS
  over HTTPS to public resolvers to evade the local filter (T1572).
- **Self-learning intelligence classifier** (`intelligence/`) — see §8.

## 2. Network & host firewall

- **Outbound IP firewall** (`firewall.py`) — blocks connections to threat-intel
  IP ranges and DoH resolver IPs via `netsh advfirewall` rules, plus a fast
  in-process IP-set membership check (`_IPSet`) for answer-IP screening.
  Protected ranges (RFC1918, loopback, the configured upstream) can never be
  blocked. *Boundary: userland `netsh`, not a kernel minifilter.*
- **Rust accelerator** (`rust/valkyrie_accel`) — optional native IP-set/CIDR
  matcher (ADR 0010); the engine auto-detects and uses it, falling back to pure
  Python when absent.
- **Network connection telemetry** (`network_telemetry.py`) — polls outbound
  connections and raises a high-severity event when one targets a threat-intel
  IP (the hard-coded-IP-C2 case DNS can't see).
- **TCP/IP fingerprint normalization** (`fingerprint.py`) — reduces
  network-stack fingerprinting exposure.

## 3. Endpoint detection & response (EDR)

The behavioral heart of the platform (`valkyrie/edr/`), fed by these sensors:

- **Process telemetry** (`process_telemetry.py`) — new-process visibility with
  full command line + parent-process chain; heuristics for LOLBins,
  Office-spawns-shell, temp/download execution, encoded PowerShell, download
  cradles, hidden-window / silent-batch flags.
- **Persistence (ASEP) telemetry** (`persistence_telemetry.py`) — detects new
  Run/RunOnce/Winlogon keys, services, Scheduled Tasks, and Startup-folder
  entries (T1547/T1543/T1053), escalating on suspicious commands.
- **Real-time ETW sensors** (`valkyrie/etw/`, ADR 0003) — dependency-free,
  no-console readers over ETW-backed event-log channels:
  - **PowerShell** script-block (4104) — encoded/download/AMSI-bypass/Defender-
    tamper/credential/injection (`classify_powershell`).
  - **WMI-Activity** — permanent event-subscription persistence, T1546.003
    (`classify_wmi`).
  - **Sysmon** (optional, auto-detected) — process w/ hashes+signature,
    network-with-process, unsigned module loads, CreateRemoteThread injection
    (T1055), LSASS access (T1003.001), registry/startup persistence, process
    tampering (`classify_sysmon`).
- **Detections → incidents** (`edr/engine.py`, `edr/schema.py`) — cheap
  detections are correlated into a small set of triable incidents with
  severity, MITRE ATT&CK technique (per detection), a timeline and an
  affected entity/process. (Correction: an earlier version of this doc
  claimed a process-tree field on the incident model; `Incident` in
  `edr/schema.py` has no such field. Process ancestry exists as a separate
  capability — `forensics.py: collect_process_tree()` and the parent-chain
  walk in `process_telemetry.py` — not yet attached to an incident.)
- **Threat hunting** (`edr/hunt.py`) — saved and ad-hoc queries over the event
  store, parameterised (never raw SQL) via `GET /api/edr/hunt/saved` /
  `POST /api/edr/hunt`. Surfaced in the desktop app as the **Threat Hunting**
  page: saved-hunt chips, a 24h quick-pivot summary, and an ad-hoc filter form.
- **Investigation + AI** (`edr/investigate.py`, ADR 0020) — builds an incident
  report (meaning, evidence, recommended actions) and an **evidence-grounded AI
  narrative** that only references real evidence, never invents detections, and
  is enum-bounded to shipped response actions. Explain-only; offline fallback.
- **Response** (`edr/response.py`) — audited, reversible actions: block domain,
  isolate host, suspend/kill process, collect forensics — dry-run by default.
- **SOAR playbooks** (`edr/playbooks.py`, ADR 0018) — YAML incident→response
  automation through the audited response manager; dry-run default, enforce
  opt-in, per-target cooldowns.
- **Forensic triage** (`forensics.py`, ADR 0017) — one-click per-incident
  evidence bundle (incident + timeline, ±30 min events, process tree,
  connections, ASEP, host facts) with a SHA-256 manifest and tamper-detecting
  verification.

## 4. Ransomware Shield (`ransomware_shield.py`)

Fully local behavioral defense: **canary tripwires** in every real user's
document folders, **entropy confirmation** (encrypted output ≈ 7.99 bits/byte),
per-process disk-I/O **attribution**, and a response that **suspends** the writer
in place (reversible) and raises a CRITICAL T1486 incident. *Boundary: reactive,
not pre-write blocking; deterministic pre-write block + rollback needs a signed
filesystem minifilter (documented extension point).*

## 5. Threat intelligence (`threat_intel.py`, ADR 0015)

Pulls real public IOC feeds — **Feodo Tracker** (C2 IPs), **URLhaus** (malware
domains), **ThreatFox** (C2 ip:port) — caches them on disk, and matches locally
in ~1 µs. Enforced at three seams: DNS decision, resolved-answer C2-IP
sinkholing, and network-collector → EDR incidents. Downloads are opt-in; feeds
are revalidated line-by-line so private/reserved IPs can never enter the match
set. (SSLBL was evaluated and rejected — deprecated upstream.)

## 6. Behavioral / self-learning intelligence (`valkyrie/intelligence/`)

- **Anomaly & baseline** — learns each process's normal destinations and flags
  departures from the learned baseline.
- **Co-occurrence & threat graph** — relates domains/infrastructure so blocking
  one learned threat surfaces related infrastructure.
- **Memory** — remembers verdicts so repeat lookups take a fast path.
- **Self-heal** (`intelligence/self_heal.py`) — watchdog that restarts failed
  subsystems and keeps the platform running.
  *All list-free and local; not a global/cloud ML model (see boundaries).*

## 7. DGA C2 detection (`dga.py`, ADR 0024)

Corroborated, precision-first detection of algorithmically-generated
command-and-control domains (T1568.002). Scores only the registrable label (so
CDN hash hostnames are structurally ignored) and fires only when length,
entropy, and an embedded **bigram-implausibility** model all agree. Wired into
the site scanner → blocks with category `dga` and raises a high-severity EDR
incident. **Measured: 0% → 76% recall at 100% precision, 0% FPR** on a hard
CDN/brand/foreign benign set. *Boundary: long-label families only; short-label
DGAs need an internet-scale model — not faked.*

## 8. Privacy hardening

- **Windows telemetry killer** (`telemetry_killer.py`) — reversible registry +
  service edits that cut OS-level tracking at the source.
- **MAC randomization** (`mac_randomizer.py`) — randomizes adapter MAC identity.
- **Zero-log mode** (`zero_log.py`) — RAM-only operation with log-integrity
  verification for privacy-critical sessions.
- **Meeting Mode** (`meeting_mode.py`) — one-command network kill switch for
  sensitive moments.
- **TLS inspection** (`tls_inspector.py`, `tls_addon.py`) — optional in-process
  mitmproxy to apply the same decision pipeline to HTTPS flows (opt-in).

## 9. Secure networking

- **Multi-hop WireGuard VPN** (`multihop.py`, `wireguard.py`) — generates
  multi-hop WireGuard configs for encrypted, chained transport.

## 10. Enterprise & operations

- **SIEM export** (`siem.py`, ADR 0016) — streams incidents as **CEF** or **JSON
  Lines** over udp/tcp/tls/file; queue-buffered, reconnecting. OFF by default;
  incident export opt-in, domain-carrying DNS export a second explicit opt-in.
- **Compliance evidence reports** (`compliance.py`, ADR 0019) — live-computed
  MTTR / coverage / audit-trail as JSON + Markdown, with an honest
  evidence-not-certification disclaimer.
- **Fleet management** (`valkyrie/fleet/`) — multi-endpoint agent/controller/
  server, signed policy distribution, and command dispatch for managing many
  protected machines.
- **Component registry** (`components.py`, ADR 0021) — uniform health / metrics /
  status / restart contract over ~15 subsystems; `GET /api/components`,
  token-gated restart, health-transition events. Surfaced in the desktop app
  as the **Components** page (per-subsystem health badge, expandable raw
  metrics, arm-then-confirm restart).
- **Signed auto-update** (`updater.py`) — signature-verified update
  verification (the security-critical half of the local update path).

## 11. Platform & reliability

- **Normalized telemetry schema** (`telemetry.py`, ADR 0011) + **event bus**
  (`eventbus.py`, ADR 0007) + **application context / DI** (`context.py`,
  ADR 0008) — one schema, one bus, one wiring surface.
- **Plugin trust gate** (ADR 0009) + **detection/enrichment plugin contract**
  (`edr/plugins.py`) — detectors and enrichers are pluggable.
- **SQLite persistence** (`store.py`, `edr/store.py`) — the single event/incident
  store, with a careful connection lifecycle (close-vs-commit).
- **Layered, validated config** (`config.py`, `settings.py`, `rules.py`,
  ADR 0006) — defaults + overlays + YAML user rules, validated.
- **Startup self-test & heartbeat** (`self_test.py`) — verifies protection at
  boot and continuously; no silent failure.
- **Windowless startup** (ADR 0001) — the engine is GUI-subsystem so it never
  flashes a console; release-gated by a no-console test.
- **Graceful degradation** — every sensor/subsystem isolates failures, restarts
  independently, and degrades to a no-op rather than crashing the platform.

## 12. Desktop application (`electron/`)

A premium **black-and-white** Chromium/Electron desktop app (custom title bar,
cinematic splash, live pages) talking to the engine only through a sandboxed
`window.valkyrie` IPC bridge — no Node, no localhost surface in the renderer.
Pages: Dashboard (protection orb + live stats), Protection, Privacy, Firewall,
Threats/EDR, Intelligence, Applications, Network, DNS, Devices, Updates,
Settings, About. Ships as a one-file NSIS installer (`ValkyrieSetup.exe`) that
installs the service + app with shortcuts and auto-launch; also a portable build.

## 13. Validation program (the trust engine)

- **Detection-efficacy harness** (`tests/efficacy/`, ADRs 0022–0024) — drives
  the **real** classifiers with a MITRE-tagged malicious corpus + benign
  controls; scores recall / FPR / precision as a **CI regression gate** (fails
  under 85% recall or over 5% FPR). Currently **30/30 recall, 0/29 FPR** across
  10+ ATT&CK techniques.
- **Unit + integration suite** (`tests/`, CI in `.github/workflows/`) — 40+
  standalone tests; Rust-backend job; syntax/lint gate.

---

## Honest boundaries — what Valkyrie does NOT do (and won't fake)

Per project policy, capabilities needing external scale or a signed kernel driver
are built as the strongest **local** version with clean extension points, and
labeled — never faked:

- **No kernel driver.** Firewall is userland `netsh`; sensors are userland
  pollers + ETW event-log readers, not a kernel ETW consumer or minifilter.
  Deterministic pre-write ransomware blocking, exact-PID attribution, and
  tamper-proof kernel telemetry require a signed driver — documented seams.
- **No signature-based file AV.** Valkyrie does not ship a malware signature
  engine; the intended path is integrating the OS's AMSI/Defender rather than
  faking an internet-scale signature cloud.
- **No global/cloud ML.** The intelligence layer is local and list-free; a
  cloud model trained on millions of endpoints (incl. short-label DGA) is
  architecture-only, marked "needs infra."
- **Efficacy numbers measure classifier discrimination** on technique-
  representative inputs, **not** live-malware detection or sensor capture. The
  gold standard (Atomic Red Team + a lab beacon in an isolated VM) is the
  documented next step, complemented — not replaced — by the in-repo harness.

See `docs/GAP_ANALYSIS.md` for the honest capability ranking vs commercial EDRs.
