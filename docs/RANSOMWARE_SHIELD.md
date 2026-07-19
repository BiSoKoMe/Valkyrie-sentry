# Ransomware Shield

Local, behavioral ransomware defense for Valkyrie. No cloud, no signatures, no
global telemetry — it detects ransomware by *what it does to your files* and
stops it. Module: [`valkyrie/ransomware_shield.py`](../valkyrie/ransomware_shield.py).

## Why this exists
Ransomware is the most destructive endpoint threat, and Valkyrie previously had
zero coverage. Unlike signature-based malware detection (which needs research
infrastructure at scale), effective ransomware defense **can** be built locally:
the behavior — mass file enumeration + encryption — is observable on one machine.
See [GAP_ANALYSIS.md](GAP_ANALYSIS.md) for why this was the highest-value gap.

## How it works (defense in depth)

1. **Canary tripwires (primary signal).**
   Decoy files are planted in the areas ransomware targets — **every real user
   profile's** `Documents / Desktop / Pictures / Downloads`, inside a
   `Valkyrie Protected` folder (the engine runs as SYSTEM, so it enumerates
   `C:\Users\*` rather than the service profile). Names sit at the alphabetical
   extremes across prized file types (`.docx/.xlsx/.pdf/.jpg`) so sequential
   encryptors hit them early. Normal software never touches these exact files,
   so a modified/deleted/renamed canary is a **near-zero-false-positive** signal.

2. **Entropy confirmation.**
   A tripped canary is read back and its Shannon entropy computed. Encrypted
   output is ~7.99 bits/byte; `>= 7.5` is flagged `encrypted`. This corroborates
   real encryption vs. an accidental touch. (Note: a canary *modification alone*
   already raises the incident — entropy enriches, it does not gate.)

3. **I/O attribution (heuristic).**
   The likely culprit is ranked by recent disk **write-byte delta** per process
   (`psutil.io_counters()`, sampled each poll), boosted 4× if the process has an
   open handle inside the affected directory. System-critical processes are never
   candidates.

4. **Response (configurable, reversible-first).**
   - `monitor` — alert + incident only.
   - `suspend` *(default)* — **suspend** the top 1–2 suspects. Suspension is
     reversible and halts encryption in place, so a false positive is recoverable.
   - `kill` — terminate.
   A **CRITICAL** incident (MITRE **T1486 — Data Encrypted for Impact**) is raised
   through the existing EDR correlation pipeline (timeline + WebSocket + dashboard),
   and tripped canaries are restored so the tripwire re-arms.

## Architecture & integration
- Emits a `Detection` via `EdrEngine.report_detection()` → same correlation →
  incident → timeline → live WebSocket path as every other sensor. No parallel
  UI or store.
- Wired in the composition root (`valkyrie/__main__.py`, step 9d); registered
  with the **self-healing** watchdog so a dead monitor thread is restarted and
  canaries re-armed; stopped cleanly on shutdown.
- Observable at `GET /api/ransomware/status`; a safe, token-gated
  `POST /api/ransomware/self-test` runs the full detection path against a
  throwaway temp canary (touches nothing real).

## Non-functional properties
- **Performance:** polls a few dozen canaries every 2 s; hashing that set 50×
  is < 1 s (benchmarked in tests). Negligible CPU; entropy is computed only on a
  trip.
- **Reliability / recovery:** the monitor loop never lets an exception escape;
  the canary manifest is persisted to `%ProgramData%\Valkyrie` and reloaded +
  re-deployed on start, surviving restarts and crashes.
- **Safety:** conservative default (suspend), hard allow-list of protected
  system processes, and a cooldown that debounces repeated trips.
- **Config:** `RANSOMWARE_SHIELD_ENABLED`, `RANSOMWARE_RESPONSE_MODE`,
  `RANSOMWARE_POLL_INTERVAL` (config.py) and `--no-ransomware-shield` (CLI).
- **Tests:** [`tests/test_ransomware_shield.py`](../tests/test_ransomware_shield.py)
  — entropy, canary lifecycle, persistence, live trip→incident, status shape,
  safe-default, and a performance benchmark. 8/8 green.

## Honest capability boundary (what we do NOT claim)
This is the strongest defense achievable **in user space**. It is not equivalent
to a commercial kernel product, and we do not pretend otherwise:

| Limitation | Why | Extension point for parity |
|---|---|---|
| Detection is *reactive* — a few files may be encrypted before a canary trips and the process is suspended. | User-space polling can't block an individual write. | **Signed filesystem minifilter driver** intercepting `IRP_MJ_WRITE`, blocking pre-write with exact PID attribution. Clean seam: replace the canary poll + I/O heuristic with driver callbacks feeding the same `report_detection()`. |
| Attribution is a heuristic (top disk writer), not proof. | No kernel file-I/O→PID mapping in user space. | Minifilter or ETW `Microsoft-Windows-Kernel-File` provider gives per-write PID. |
| No rollback of already-encrypted files. | We halt, we don't restore. | Volume Shadow Copy (VSS) snapshotting + restore of affected paths. |
| No ransomware-family intelligence. | Needs research infra. | Optional threat-intel feed integration (documented as needs-infra in the gap analysis). |
| Canaries can be skipped by ransomware that avoids odd filenames/folders. | Heuristic decoys aren't exhaustive. | Minifilter covers all writes regardless of decoys; also add entropy-rate monitoring across real files via ETW. |

The design intentionally routes the driver/ETW/VSS upgrades through the same
`Detection` → incident interface, so reaching commercial parity is an additive
change, not a rewrite.
