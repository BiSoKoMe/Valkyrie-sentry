# Valkyrie & NYX — Every Process, End to End

A complete walkthrough of what actually runs, in what order, and what each stage
does with the data it is handed. Grounded in the shipped code (file:function
cited throughout), not an idealised diagram.

Two systems live here and the split is deliberate:

- **Valkyrie is the platform / the body.** It owns your *network presence* (what
  your machine looks like from outside), the system-protection layer (EDR
  detection, firewall, response), and the app/service shell.
- **NYX is the core / the data brain.** It owns *you as data*: what is read from
  you, what escapes you, and lying to whoever reaches for it.

---

## 0. Boot — how the engine starts

`valkyrie/__main__.py` is the composition root. It builds every subsystem and
injects them; nothing reaches for a global singleton.

The order matters and was rebuilt around one rule — **liveness before
readiness**:

1. **Store** (`store.Store`) — the SQLite event/detection/incident database,
   started first because everything writes to it.
2. **Web dashboard bound EARLY** (`__main__.py` §1b) — the FastAPI/uvicorn API
   is started *now*, on a context holding only the store, and the code blocks
   until the socket is actually listening (~1 s). This is the fix for a real
   failure: the server used to be built last, so `/api/health` could not answer
   until every heavy subsystem had finished, and on a constrained host that took
   minutes. Every route tolerates a not-yet-ready (`None`) field, so "is the
   process alive?" is answerable immediately while "is protection warm?" fills in
   behind it.
3. **Blocklist → threat intel → firewall → resolver/Unbound → rules → process
   watcher → behavioral engine → site scanner → intelligence → MAC randomiser →
   DoH detector → content watch → deception → DNS interceptor → baseline →
   heartbeat → EDR engine.**
4. **Subsystems attach** to the already-running web context (`__main__.py` §10) —
   the same mutable `AppContext` object the server holds by reference, so the
   dashboard lights up at once.
5. **TLS inspector** last (it needs a started engine), then attached too.

Two safety threads run alongside: the **self-healing watchdog** (checks
components every 30 s, restarts dead ones) and the **heartbeat/self-test**.

---

# PART ONE — VALKYRIE (the platform)

## 1. The DNS path — every name your machine resolves

`valkyrie/dns_interceptor.py` listens on `127.0.0.1:5353`. Each query is decided
**inline** — there is no polling, no queue, the answer is computed in the request
path:

1. **Parse** the query name.
2. **Blocklist check** (`blocklist.py`) — the bulk tracker/ad/malware list.
3. **Threat-intel check** (`threat_intel.py`) — IOC feeds (URLhaus, Feodo).
4. **CNAME uncloaking** (`cname_uncloak.py`) — resolves the chain and re-checks
   the *target*, so a first-party-looking `metrics.brand.com` that CNAMEs to a
   known tracker is still caught.
5. **DGA / tunnel detection** (`dga.py`, `dns_tunnel.py`) — algorithmically
   generated C2 domains and DNS-tunnelled exfil, by shape not by list.
6. **Popular-domain floor** (`popular_domains.py`) — an FP guard: a
   widely-used domain needs much stronger evidence before it is ever blocked.
7. **Decision** → one of: **allow**, **sinkhole** (return `0.0.0.0`), or
   **deceive** (return a decoy IP so the tracker gets a plausible lie rather
   than an obvious block).
8. **Record** (`resolution_log.py`) and emit an event to the store.

Everything above is a Valkyrie-platform concern (network presence). The *why is
this domain bad* judgement for trackers is NYX's vocabulary, applied here.

## 2. The process path — every program that runs

Three sensors feed the same normalised schema (`valkyrie/edr/schema.py`):

- **`etw/sysmon.py`** — Sysmon EID 1/3/7/8/10 (process create *with command
  line*, network connect, image load, remote thread, process access). The
  richest source.
- **`native_audit.py`** — Windows Security 4688 + command line. The fallback
  when Sysmon is absent; the engine auto-enables it when run elevated.
- **`process_telemetry.py`** — a ~2 s poller. Catches what the others miss but
  loses short-lived processes by design (documented, not hidden).

Each process event then runs the **detection stack**, in this order
(`etw/sysmon.py:_on_event`):

1. **`classify_process`** — intrinsic properties (path, signature, name).
2. **`cmdline_normalize.normalize_cmdline`** — strips obfuscation *before*
   matching: unicode homoglyphs, caret/backtick escapes, quote-splitting,
   string concat, format operators, char arithmetic, env-var expansion, base64
   payload decoding, delimiter folding (`,`/`;`), whitespace. Runs as a
   fixed-point loop so stacked tricks unwind. Rules match **both** the original
   and the normalised text, so normalisation can only *add* detections.
3. **`classify_cmdline`** — encoded-PowerShell, download-cradle heuristics.
4. **`behavioral_rules.classify_behavior`** — **168 IOA rules**, each a named
   ATT&CK-mapped behaviour shape (not a hash, not a literal string). This is the
   recall layer.
5. **`behavior_score.py`** — the *generalizing nose*. A weak-signal ensemble
   scoring intrinsic "wrongness": masquerading system name, execution from a
   low-trust directory, measured obfuscation, impossible parent→child lineage,
   machine-generated or double-extension names. No single weak signal fires;
   compounding ones do. **This is what catches malware no rule was written for.**
6. **`behavioral_sequences.py`** — named multi-step IOAs (e.g.
   *reconnaissance-burst*: ≥3 distinct discovery techniques from one actor
   within 300 s).

## 3. Correlation — turning events into one story

Every event (**not just detections**) is stitched into the graph
(`edr/engine.py:387` → `edr/causality.py`):

- **`causality.py`** — a process-ancestry graph. Nodes are keyed
  `(pid, create_time)` so PID reuse can't corrupt lineage. Non-process events —
  DNS, network, file, registry, detections — are *attributed* to the process
  that caused them. **Causality terminators** stop the upward walk below OS
  infrastructure (`explorer.exe`, `services.exe`, `svchost.exe`) so the root is
  the *Causality Group Owner* — the document or download that started it, not
  `System`. Terminator status is path-aware: a `svchost.exe` in `%TEMP%` does
  **not** terminate the walk, because that masquerade is exactly what the
  ancestry would expose.
- **`killchain.py`** — scores the *sequence*. One tactic is business as usual;
  three distinct ATT&CK tactics from one actor in a short window is an
  intrusion. Pure function of distinct tactics + a bump for high-impact ones.
  Honest boundary: it raises **no new primary signal** — it escalates confidence
  when independent detectors already agree.

## 4. Decision — what the evidence justifies

`decision.py:decide()` maps a signal to one rung of a five-step ladder:
**ALLOW → ALERT → DECEIVE → BLOCK → CONTAIN**, given a threat class
(surveillance / compromise / metadata-leak / decoy-trigger) and a confidence,
modulated by the active risk profile (`profiles.py`).

## 5. Authority — what it is *allowed* to do

`edr/authority.py` is the part almost nothing else ships. Permission is the
**minimum** of four independent gates, then a categorical veto:

```
permitted = min(evidence, coverage, consequence, budget)
action    = veto(permitted, invariants)
```

- **evidence** — what `decide()` concluded.
- **coverage** — are the sensors that would confirm this actually live?
  (`sensor_deps.py`). A high-confidence detection on dark sensors is *not*
  authorised.
- **consequence** — is the action reversible or leasable? (`reversibility.py`,
  `leases.py`). An irreversible action may never be reached by a signal that was
  already degraded.
- **budget** — has it acted a lot already? (`cascade.py`).
- **invariants** — categorical vetoes that overrule everything.

They take the floor, never an average — so no single strong signal can buy
authority it hasn't earned on another axis.

## 6. Response — doing it

`edr/response.py` executes through one audited path: `block_domain`,
`kill_process`, `isolate_host`, `remove_persistence` (+ their inverses).
`isolate_host` snapshots the *entire* firewall state first and refuses to
isolate if it can't capture a way back.

`edr/remediation.py` **constructs** the plan from the causality subgraph rather
than selecting a template: every action cites the observation that produced it,
each is authorised separately, and ordering is operational — cut C2, close the
return route, then terminate, then contain. A hole in the graph (truncated walk,
inferred ancestry) caps irreversible actions.

## 7. Host safety — the floor under everything

`host_safety.py` — a fail-safe watchdog that guarantees Valkyrie never leaves the
machine worse than it found it. It records the host's real DNS and, the instant
the adapter is loopback-routed to a Valkyrie resolver that has stopped answering,
restores connectivity (exact original, else DHCP). A watchdog, not a cleanup
handler, so it survives a crash, a kill, or a replaced build.

---

# PART TWO — NYX (the data brain)

NYX owns two things: **stopping your data leaving**, and **giving fake info to
whoever reaches for it**. It runs in the TLS path.

## 8. The TLS path — every request your browser makes

`tls_addon.py:ValkyrieAddon` is a mitmproxy addon with two hooks.

### On the REQUEST (`_handle_request`)

1. **Tracking-parameter stripping** (`_strip_tracking_params`) — removes
   `utm_*`, `fbclid`, `gclid` and friends from the URL.
2. **Tracker-path detection** (`_is_tracker_path`) — `/collect`, `/pixel`,
   `/beacon`, `/tr`, `/v1/batch` … the beacon endpoints themselves.
3. **Fingerprint-script detection** (`_is_fingerprint_path`) —
   `fingerprintjs`, `fp.js`, `evercookie`, `canvas-fingerprint` …
4. **NYX outbound inspection** (`tls_addon.py:313` → `nyx.inspect_outbound`) —
   the core. See §9.
5. **NYX act mode** (`tls_addon.py:319` → `nyx.fake_outbound`) — when
   `config.NYX_ACT` is on, the request is **rewritten** and still completes. See
   §10.

### On the RESPONSE (`_handle_response`)

6. **HTML/JS cleaning** (`_clean_html_regex`) — third-party tracker `<script>`
   tags removed; inline analytics calls (`fbq`, `gtag`, `ga`, `mixpanel`,
   `heap`, `hj`) neutralised — the tag stays so the page's JS doesn't throw, but
   the call becomes a no-op. **Never break the page** is the prime directive.
7. **Farbling** (`farble.py`) — canvas/audio/WebGL readouts get tiny,
   *per-session-consistent* noise so a fingerprinter gets a stable but false
   identity rather than an obviously-blocked surface.

## 9. NYX inspection — what is leaving, and is it yours?

`nyx.py:inspect_outbound(method, url, headers, body)` — pure, returns
`Observation` objects, never mutates the request.

**The third-party gate first:** the registrable domain of the *page* (from
`Referer`/`Origin`) is compared to the destination. Same-party traffic is not
judged — sending your email to the site you're logging into is not a leak.

Then six categories are detected **by data shape**, not by domain list:

| Category | What it recognises |
|---|---|
| `identifier` | advertising/device IDs — `adid`, `idfa`, `gaid`, GUIDs, long opaque tokens |
| `location` | a latitude **and** longitude, or a lat/lon pair |
| `contact` | email addresses, E.164 phone numbers |
| `fingerprint` | a **bundle** of ≥3 device surfaces (see below) |
| `financial` | a **Luhn-valid** payment card number |
| `cookie` | a persistent, high-entropy third-party cookie (entropy proxy, not a list) |

**The fingerprint bundle** is the FP guard in action — it requires **≥3 distinct
surfaces** in one request before firing: screen/resolution, timezone, language,
CPU cores/memory, canvas/WebGL/GPU, user-agent, **audio** (AudioContext,
oscillator, audio hash), **font enumeration** (a comma-separated font list), and
**WebRTC local-IP leak** (an RFC1918 address crossing to a third party — your LAN
address exposed from behind a VPN). One signal alone is never a fingerprint.

Every observation is **masked** before it is shown or stored — NYX reports *that*
your email leaked, not the email.

## 10. NYX action — the lie, not the block

`nyx.py:fake_outbound(...)` (gated by `config.NYX_ACT`, default off).

The design choice that defines NYX: **deception over blocking.** A blocked
beacon tells the tracker it was blocked and may break the page. A *replaced*
beacon completes normally — the tracker gets a coherent, believable identity that
simply isn't you.

The fakes come from **one consistent persona** (`persona.py`) — a stable fake
device ID, location, email, and card — so a tracker correlating across requests
sees a *plausible person*, not random noise that would flag as evasion.

`deception.py` serves plausible replies to intercepted beacons (a valid pixel, a
`204`, a well-formed JSON ack) so nothing downstream errors.

## 11. NYX correlation — one tracker, many masks

`nyx_graph.py` — the on-device correlation layer. Links a tracking *organisation*
to all the identities it wears (different hostnames, CNAME aliases, app
endpoints) so the user can be told "this company followed you across 14 sites
under 6 different names" instead of 14 unrelated blocks. This is the local
equivalent of a threat graph — done entirely on the machine, which is the thing
no cloud vendor's architecture permits.

---

## 12. What comes out — reporting

- **Store** — events, detections, incidents (SQLite, `data/valkyrie.db`).
- **API** — `/api/health`, `/api/stats`, `/api/nyx`, `/api/edr/incidents`,
  `/api/controls/coverage` … all cached (`web/cache.py`) so a slow probe can
  never starve the event loop.
- **Dashboard** — the Electron app (START/STOP + the SOC views) and the
  browser dashboard on `:8090`.
- **SIEM export** (`siem.py`), **forensics triage** (`forensics.py`),
  **compliance reports**.
- **Evidence librarian** (`redteam/evaluation/evidence.py`) — the layer that
  makes a *test report* incapable of lying: raw evidence / test state /
  detection result / measurement validity kept separate, a detection requires
  the whole chain (attack executed → engine responsive → telemetry present →
  detection linked to the attack), contradictions block the score, and the
  denominator excludes what never ran.

---

## 13. The honest boundaries

- **Sysmon dependency** — the richest sensor is a third-party tool that can be
  stripped by another security product (this happened; see ADR 0048). Valkyrie
  degrades to 4688 rather than going silently blind.
- **The kill chain originates nothing** — it escalates existing detections. A
  chain the sensors never saw cannot be conjured.
- **The kernel driver is compiled but unsigned** and must never be loaded.
  Signing is a business step (EV cert + attestation), not an engineering one.
- **No cross-customer intelligence.** By design — sending your telemetry to a
  cloud is the thing NYX exists to prevent. The trade is real: no global
  campaign correlation, in exchange for data that never leaves the machine.
- **Measured live detection: ~71% of validly-measurable techniques** in the
  57-technique Tier B breadth battery; NYX battery 68/71 with **0 false
  positives**. Both scored through the librarian, not self-reported.
