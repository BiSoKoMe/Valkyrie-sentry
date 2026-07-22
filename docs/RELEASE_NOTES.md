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
  shipped responders, guarded by a regression test. `edr/investigate.py`. **Now
  surfaced in the app**, not just the API: open any incident's Replay and
  switch to the new **Investigation** tab for the offline analysis (what
  happened, why it matters, recommended response with rationale), an explicit
  opt-in "Ask AI" for a deeper narrative (never called automatically — same
  opt-in-by-default stance as the rest of the app), and a **Triage** panel
  (status, assignee, analyst notes) that writes through the existing audited
  `POST /api/edr/incidents/{id}/status` endpoint. This backend has been fully
  built and tested since before 0.1 shipped; it had no UI until this pass —
  closing that gap was higher priority than any new page.
- **Detection-efficacy harness + CI gate** (ADRs 0022–0024) — drives the real
  classifiers against a MITRE-tagged corpus and fails CI if recall < 85 % or
  FPR > 5 %.
- **Premium monochrome desktop app** — black / white / grey with a single
  restrained blue accent, custom title bar, cinematic splash, and a reusable
  design-system state component (empty / offline / error).
- **Component Health page** — the uniform health/metrics/restart contract
  every subsystem already runs through (`components.py`, ADR 0021 — DNS,
  firewall, EDR, sensors, threat intel, SIEM, and more) had a fully-built,
  token-gated API (`GET /api/components`, `POST /{name}/restart`) and no UI.
  Now it's the **Components** page: live health badge per subsystem
  (healthy / degraded / down / disabled / **error** — a health probe that
  itself throws is shown as an error state, not silently hidden), expandable
  raw metrics, and a restart control that requires arming before it fires
  (restarting a live security subsystem has real effect — a brief gap in
  that subsystem's coverage — so it doesn't fire on a single misclick).
- **Threat Hunting page** — the third "fully-built backend, zero UI" gap
  found this pass: `edr/hunt.py` is a real, safe, read-only query surface
  (a small validated filter spec compiled to parameterised SQL — never
  arbitrary queries) with six saved hunts ("beacon candidates," "noisiest
  talkers," "rare domains," …) and a facets endpoint, all already wired to
  `GET /api/edr/hunt/saved` / `POST /api/edr/hunt`, with no page calling
  either. Now a page: saved-hunt chips, a 24h quick-pivot summary (top
  processes/categories/decisions, also seeding the category field's
  suggestions from real observed data), an ad-hoc filter form matching
  exactly the fields the backend accepts, and a results table whose columns
  are read from whatever the query actually returned — different hunts
  return different shapes, so the table doesn't assume one. No query
  language, autocomplete-from-history, or saved/pinned queries are implied
  beyond what the backend supports.
- **Compliance evidence page** — the fourth backend-with-no-UI gap this pass:
  `compliance.py` computes a live SOC 2 / ISO 27001 evidence report
  (monitoring coverage, incident MTTR, threat-intel freshness, audit trail)
  with an explicit "evidence, not certification" disclaimer built into the
  API response itself — and no page ever called it. Now a page: the
  disclaimer shown verbatim and first (never buried), a period selector,
  summary cards, and a per-section breakdown with each framework reference
  (SOC 2 / ISO 27001 control ID) the section is evidence toward. Adds a
  "Copy as Markdown" action against the same endpoint's `?format=md`
  rendering — which needed a small, real architecture extension: the
  existing `api:get` IPC bridge always `JSON.parse`s the response body, so
  a plain-text endpoint would have silently failed through it. Added
  `api:getText` (same `/api/*` allowlist, same 4 s timeout, no JSON parsing)
  rather than build a feature on a call path that would reject its own
  response (`electron/src/main/engine.js`, `main.js`, `preload.js`).
- **Command palette (Ctrl+K)** — instant, keyboard-first search over the app's
  16 pages, 5 quick actions (start/stop protection, meeting mode, kill
  telemetry, randomize MAC, open logs), and recent EDR incidents (jumps
  straight into Replay). Ranking is pure, unit-tested logic
  (`electron/src/renderer/command-index.js`); every action it runs is the
  *exact* shared function a page's own button calls — no second
  implementation to drift out of sync. Reports live results via toast
  feedback (`electron/src/renderer/app.js` `toast()`), a new reusable
  component of the design system.

## Reliability & trust fixes in 0.1

- **Never show false reassurance.** The Threats view previously showed
  "endpoint is clean" even when the engine was not running. It now distinguishes
  **"Protection is off — not monitoring"** from **"monitoring, no incidents"** —
  a security product must never imply safety while protection is down. Delivered
  via a reusable `stateBlock()` empty/offline/error component, now rolled out to
  every live panel that can be observed before protection is ever started:
  Dashboard (recent activity feed), Firewall and DNS (top-blocked lists),
  Applications (process activity), Privacy and Intelligence (subsystem status).
  Each panel used to show a generic "no data yet" message regardless of whether
  the engine was actually running — indistinguishable from "checked, found
  nothing." The offline/empty split is pure decision logic
  (`electron/src/renderer/view-state.js`, unit tested independently of the DOM:
  `npm test` in `electron/`) so the same honesty guarantee is easy to extend to
  any future panel.
- Graceful degradation is a platform rule: every sensor/subsystem isolates
  failures, restarts independently, and degrades to a no-op rather than crashing
  the app. The renderer talks to the engine only through a sandboxed IPC bridge.
- **Keyboard accessibility fix.** The sidebar (16 pages) and the incident list
  on the Threats page were `<div>`s with a click handler only — invisible to
  keyboard-only and screen-reader users, a real procurement blocker for
  enterprise/accessibility-conscious buyers. Both are now proper `role="button"`
  controls with `tabindex`, Enter/Space activation, and `aria-current`/
  `aria-label`. Every interactive element also gets one consistent
  `:focus-visible` ring (the same restrained blue used elsewhere) instead of
  either no visible focus state or the unstyled browser default.
- **Keyboard-trap bug fix in Replay.** Adding the Investigation tab's form
  fields (assignee, notes) exposed a real regression: Replay's global
  transport shortcuts (Space = play/pause, ←/→ = seek) fired unconditionally
  on every keydown, so typing a space into the Notes field also toggled
  playback and ate the keystroke — the triage form was effectively broken
  for any note containing a space. Fixed by skipping transport shortcuts
  when the event target is an editable control; Escape still closes the
  modal from anywhere, matching normal dialog convention.
- **Modal focus trapping.** Replay and the Command Palette are full-screen
  overlays but Tab could leak focus out to the sidebar/page behind them —
  a real WCAG dialog violation, not just a nicety. Added one shared
  `trapFocus()` helper (cycles Tab/Shift+Tab within the open dialog) used
  by both; both also now move focus into the dialog on open and restore it
  to whatever triggered them on close, instead of leaving focus wherever it
  happened to land.
- **Reopen where you left off.** The app always restarted on Dashboard
  regardless of what the analyst was last looking at. The last-visited page
  is now remembered locally (`localStorage`, never synced) and restored on
  next launch — unless the app was opened with an explicit deep-link
  `startPage`, which still takes priority.
- **Perfected the one real data table.** The Threat Hunting results table
  had no sort and no way to get data out of the app. Added a reusable,
  unit-tested `DataTable` module (`electron/src/renderer/data-table.js`) —
  stable sort per column (click a header; numbers sort numerically, text
  sorts naturally; missing values always sort last, never first), "Copy
  CSV," "Copy JSON," and click-a-row to copy it as tab-separated text. This
  is a design-system component, not a one-off: any future table (e.g. a
  Fleet inventory view) reuses the same module instead of re-implementing
  sort/export. Buttons are labeled "Copy," not "Export" — nothing is
  written to disk, everything goes to the clipboard, matching the
  Compliance page's Markdown export.

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
- **Desktop scope for 0.1.** Attack Replay, Dashboard, Threats, Threat
  Hunting, Privacy, Firewall, DNS, Intelligence, Applications, Network,
  Devices, Updates, Components, Compliance, Settings, and About ship — 16
  pages. **Command palette (Ctrl+K) covers navigation, quick actions and
  recent incidents only** — it does not (yet) index MITRE technique
  reference data, threat-intel entries, playbooks, or log contents, because
  those don't have a real per-item detail view to jump to today; indexing
  them without a destination would be search theater, not search.
  **Not yet in the desktop app:** a full incident-detail workspace (process
  tree / network graph panels beyond Replay), a SOAR / Forensics UI
  (`edr/playbooks.py`, `forensics.py`), and a Fleet management UI
  (`fleet/`) — each a real, tested backend module with no desktop surface
  yet. These are planned follow-ups, not implied to exist today.
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
| Dashboard / Threats / Privacy / Firewall / DNS / Components / Compliance / Settings / About | ✅ |
| Threat Hunting (saved hunts, quick pivots, ad-hoc filter query) | ✅ read-only, backed by `edr/hunt.py` |
| Attack Reconstruction (Replay Mode) | ✅ |
| Investigation explainability (meaning + actions, all categories) | ✅ |
| Vendor-neutral AI, opt-in | ✅ |
| Tests passing; efficacy gate green | ✅ |
| Honest empty/offline/error states (reusable component) | ✅ Threats, Dashboard, Firewall, DNS, Applications, Privacy, Intelligence |
| Command palette (Ctrl+K) | ✅ navigation, quick actions, recent incidents — not full cross-entity search |
| Toast notifications (reusable component) | ✅ |
| Incident investigation + triage (Replay → Investigation tab) | ✅ explainability, recommended response, status/assignee/notes |
| Keyboard-accessible sidebar + incident list, app-wide focus ring | ✅ |
| Component health page (per-subsystem status, metrics, restart) | ✅ ~15 subsystems, arm-then-confirm restart |
| Compliance evidence page (SOC 2 / ISO 27001, MTTR, Markdown export) | ✅ backed by `compliance.py` |
| Modal focus trapping (Replay, Command Palette) | ✅ shared `trapFocus()`, focus returns to opener on close |
| Reopen on last-visited page | ✅ `localStorage`, deep-link `startPage` still takes priority |
| Reusable sortable/exportable data table (`data-table.js`) | ✅ used by Threat Hunting; column sort, copy row, copy CSV/JSON |
| Full incident-detail workspace (process tree / network graph) | ⏳ partial (Replay covers timeline + explainability + triage; no process-tree/network-graph panels yet) |
| SOAR / Forensics UI | ⏳ backend only (`edr/playbooks.py`, `forensics.py`) |
| Fleet management UI | ⏳ backend only (`fleet/`) |
| Documentation & known limitations | ✅ (`docs/`) |

## Provenance

Built on the engineering record in `docs/adr/` (0001–0024), the measured
capability review in `docs/GAP_ANALYSIS.md`, the efficacy program in
`docs/DETECTION_EFFICACY_REPORT.md`, and the full inventory in
`docs/CAPABILITIES.md`.
