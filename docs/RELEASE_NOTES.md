# Valkyrie 0.1.0 — Release Notes

**The first production-quality release of Valkyrie** — a local-first, privacy-
first Windows security platform: a premium desktop application over a behavioral
EDR + DNS/network protection engine. Everything runs on the box; nothing leaves
the machine unless an operator explicitly enables an export.

This document is honest about what 0.1 is and is not. Capabilities that need
external scale or a signed kernel driver are shipped as the strongest *local*
version and labeled — never faked. See `docs/CAPABILITIES.md` for the full
inventory and `docs/GAP_ANALYSIS.md` for the honest ranking vs commercial EDRs.

---

## Highlights

- **Attack Replay** — open any incident and watch the attack reconstruct itself
  step-by-step from the *real* correlated telemetry: the attack chain unfolds
  chronologically, MITRE ATT&CK techniques light up in the order observed, with
  play / pause / step / scrub / 1×–4× speed and keyboard control. A signature
  investigation experience most EDRs lack. (`electron` renderer)
- **Corroborated DGA C2 detection** (ADR 0024) — precision-first detection of
  algorithmically-generated command-and-control domains (T1568.002). Measured
  **0 % → 76 % recall at 100 % precision, 0 % FPR** on a hard CDN/brand/foreign
  benign set. `valkyrie/dga.py`.
- **Vendor-neutral AI investigation** — the LLM assistant is abstracted behind a
  provider interface (Anthropic / OpenAI / local OpenAI-compatible / offline),
  all over plain HTTP, **no AI-vendor SDK dependency**. Opt-in, off by default;
  the `local` provider keeps everything on-box. `valkyrie/edr/ai_provider.py`.
- **100 % incident explainability coverage** — every incident category has a
  plain-English "what this means" and recommended actions built only from real
  shipped responders, guarded by a regression test. `edr/investigate.py`.
- **Detection-efficacy harness + CI gate** (ADRs 0022–0024) — drives the real
  classifiers against a MITRE-tagged corpus and fails CI if recall < 85 % or
  FPR > 5 %.
- **Premium monochrome desktop app** — black / white / grey with a single
  restrained blue accent, custom title bar, cinematic splash, and a reusable
  design-system state component (empty / offline / error).

## Reliability & trust fixes in 0.1

- **Never show false reassurance.** The Threats view previously showed
  "endpoint is clean" even when the engine was not running. It now distinguishes
  **"Protection is off — not monitoring"** from **"monitoring, no incidents"** —
  a security product must never imply safety while protection is down. Delivered
  via a new reusable `stateBlock()` empty/offline/error component so this stays
  consistent as more pages adopt it.
- Graceful degradation is a platform rule: every sensor/subsystem isolates
  failures, restarts independently, and degrades to a no-op rather than crashing
  the app. The renderer talks to the engine only through a sandboxed IPC bridge.

## Validation (measured, honest)

- **Detection efficacy:** 30 / 30 recall, 0 / 29 false-positive rate across 10+
  ATT&CK techniques on the in-repo corpus (`tests/efficacy/`). This measures
  **classifier discrimination on technique-representative inputs — not** live-
  malware detection or sensor capture.
- **Test suite:** 45+ standalone unit/integration tests (`tests/`), a Rust-
  accelerator job, and a syntax/lint gate in CI. The AI provider layer, EDR,
  explainability, telemetry, threat-intel, SIEM, fleet, forensics, compliance,
  scanner, DGA, and TLS suites all pass.
- **DGA detector:** 100 % recall / 100 % precision on the representative PRNG
  corpus; ~148 k classifications/sec (a pure function).
- **Installer:** `ValkyrieSetup.exe` builds green through the full release
  pipeline (`build_app.ps1`) with release-blocking audits — no developer/user
  data in the package, and a windowless-startup check (no console flash).

## Known limitations (0.1)

Honest boundaries, documented rather than hidden:

- **No kernel driver.** The firewall is userland `netsh`; sensors are userland
  pollers + ETW event-log readers, not a kernel ETW consumer or minifilter.
  Deterministic pre-write ransomware blocking and tamper-proof kernel telemetry
  require a signed driver (documented extension points).
- **No signature-based file AV** and **no global/cloud ML** — out of scope for a
  local-first product; the intended path is OS AMSI/Defender integration.
- **Desktop scope for 0.1.** Attack Replay, Dashboard, Threats, Privacy,
  Firewall, DNS, Intelligence, Applications, Network, Devices, Updates,
  Settings, and About ship. **Not yet in the desktop app:** a global command
  palette / cross-entity search, a full incident-detail workspace (process tree
  / network graph panels beyond Replay), and a Fleet management UI (the fleet
  *backend* exists). These are planned follow-ups, not implied to exist.
- **AI investigation is opt-in and off by default.** A network provider sends
  compact incident facts to the configured endpoint; use the `local` provider to
  avoid that entirely.

## Install / upgrade

- **Install:** run `ValkyrieSetup.exe` on a clean Windows 10/11 x64 machine. It
  self-elevates and installs the service + app with shortcuts and auto-launch.
- **Portable:** `ValkyriePortable.exe` runs with no install; all state lives
  beside the executable.
- **Build from source (Windows):** `./build_app.ps1` (add `-SkipEngine` for a
  renderer-only rebuild). Development: `cd electron && npm run dev`.

## Release-readiness checklist

| Item | Status |
|---|---|
| Core protection (DNS/firewall/EDR) stable | ✅ |
| Installer works on clean Windows | ✅ (release-audited build) |
| Dashboard / Threats / Privacy / Firewall / DNS / Settings / About | ✅ |
| Attack Reconstruction (Replay Mode) | ✅ |
| Investigation explainability (meaning + actions, all categories) | ✅ |
| Vendor-neutral AI, opt-in | ✅ |
| Tests passing; efficacy gate green | ✅ |
| Honest empty/offline/error states (reusable component) | ✅ Threats; rolling out to other pages |
| Global search / command palette | ⏳ planned (not in 0.1) |
| Full incident-detail workspace (process tree / network graph) | ⏳ partial (Replay covers the timeline) |
| Fleet management UI | ⏳ backend only |
| Documentation & known limitations | ✅ (`docs/`) |

## Provenance

Built on the engineering record in `docs/adr/` (0001–0024), the measured
capability review in `docs/GAP_ANALYSIS.md`, the efficacy program in
`docs/DETECTION_EFFICACY_REPORT.md`, and the full inventory in
`docs/CAPABILITIES.md`.
