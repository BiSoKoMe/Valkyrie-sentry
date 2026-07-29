# ADR 0035 — AMSI content scanning (borrow a verdict, don't fake an engine)

Date: 2026-07-28 · Status: accepted

## Context

Every endpoint verdict Valkyrie could produce was a **heuristic**. A rule matched
a command line, the anomaly scorer found a wrong-looking shape, an entropy check
crossed a threshold, a sequence completed. All real detection — and all
*suspicion*. Valkyrie had **zero content conviction**: it could say "this script
looks obfuscated" but never "this content is malicious," because it has no
signature corpus and — per the no-fake-parity rule — will not pretend to one.

`docs/GAP_ANALYSIS.md` has ranked this gap #6 ("Malware detection (files) —
needs infra") since the first review, with the honest path already written down:
*integrate the OS's AMSI/Defender; don't build a signature engine.* This ADR
executes that. It is the single largest remaining hole that does **not** require
a signed kernel driver.

## Decision

New `valkyrie/amsi.py` — a stdlib-only ctypes client for the **Antimalware Scan
Interface**, the documented Windows API that the registered antimalware provider
(Defender, or a third-party AV) answers with a real verdict on arbitrary content.

- `AmsiScanner` — `start`/`stop`/`available`/`is_healthy`/`stats`, matching every
  other subsystem so the component registry (ADR 0021) adapts it with no
  special-casing. `scan_string`, `scan_bytes`, `scan_file`.
- `classify_amsi_result` — pure mapping of the raw `AMSI_RESULT` enum onto a
  Valkyrie disposition, with both documented boundaries pinned by test. The
  `0x4000–0x4FFF` band is an **admin policy block (WDAC/AppLocker), not a
  conviction**, and the two stay distinct. Undefined results are `unknown` and
  are never treated as malware.
- **Skip, never truncate.** Content over the cap is skipped with a stated reason.
  A partial scan returning "not detected" is a misleading answer, and misleading
  is worse than absent.
- Content-hash LRU so a repeated script block costs one round trip, not N.

### Where it is wired

The PowerShell script-block sensor (`etw/powershell.py`, ADR 0003) already
captures the **deobfuscated** text PowerShell is about to run — the single
highest-value content on the box. `PowerShellSensor(scanner=…)` submits it and,
on a conviction, re-categorizes the event to the new `CAT_MALWARE` with
`critical` severity and an `amsi_detected` label.

The corroborator is **strictly additive**: a scanner that is absent, stopped,
silent, or raising leaves the sensor's heuristic output byte-for-byte unchanged.
That property is pinned by four separate tests, because a detection layer that
degrades a working one is worse than no layer.

New incident category `malware` gets its meaning, recommended responders, and
MITRE mapping (`edr/investigate.py`, `edr/builtin.py`) — the explainability gate
in `test_explainability.py` fails otherwise, by design.

### Provider presence is a fact, not an inference

The first implementation concluded "no provider" from a non-conviction on
Microsoft's AMSI test marker. **That was wrong, and live testing caught it.** On
the development host, `Get-MpComputerStatus` reports `AMServiceEnabled: False` —
Defender has stood down because Avast and McAfee are installed — and neither
third-party provider recognises the marker (nor EICAR) through AMSI.

AMSI providers are in-process COM servers: `AmsiInitialize` loads each registered
provider DLL into the *calling* process. So presence is directly observable —
`registered_providers()` reads `HKLM\SOFTWARE\Microsoft\AMSI\Providers`, resolves
each CLSID to its `InprocServer32` path, and asks the loader (`GetModuleHandleW`)
what is actually resident. That is what `provider_state()` reports.

`self_test()` is therefore **tri-state**, not pass/fail:

| Conclusion | Meaning |
|---|---|
| `confirmed` | A provider convicted the marker. Path proven end to end. |
| `inconclusive` | A provider is loaded and answering but does not know this marker. Expected for non-Defender AV — **not a failure**. |
| `no_provider` | Nothing registered or resident; AMSI is a permanent no-op here. |

`GET /api/amsi/status`; `POST /api/amsi/self-test` is token-gated (a provider
that convicts writes a detection into its own history, so a remote page must not
be able to trigger it) and is never run on a timer.

## Consequences

**Gained.** A real malware verdict on script content and files — the first
non-heuristic evidence Valkyrie can produce. Because the conviction enters the
normal `Detection` pipeline, it participates in kill-chain correlation (ADR 0025)
and the sequence IOAs (ADR 0032): "the AV convicted this script" AND "this same
lineage then touched LSASS" becomes **one** incident with one timeline. Defender
alone does not feed Valkyrie's graph; that correlation is the added value.

**Honest boundaries — stated in the module docstring and `docs/CAPABILITIES.md`:**

- `not_detected` is **not** proof of clean. It means no provider had an opinion.
- Where Defender is the provider, script content scanned here was very likely
  *already* scanned by Defender's own AMSI hook when PowerShell ran it. Valkyrie
  is **not** a second scanner and claims no added detection there. What it adds
  is file-path scanning and the correlation above.
- The verdict is the **provider's**, not Valkyrie's. We report it and name it; we
  do not re-score it or claim it as our own detection.
- This does **not** close gap #6. Valkyrie still has no signature engine and
  still cannot detect what the installed provider cannot. It borrows a verdict.
- Measured on the dev host: ~1–6 ms per scan, provider DLLs resident, conclusion
  `inconclusive`. The efficacy harness deliberately does **not** score this —
  there is no Valkyrie classifier here to measure, and scoring someone else's
  engine as our recall would be exactly the fake parity the project forbids.

**Test-marker handling.** The AMSI marker is assembled at runtime from fragments
rather than written as one literal, so a scanner reading `valkyrie/amsi.py`
cannot quarantine Valkyrie's own source. The value is byte-identical at scan
time; only the on-disk representation differs.

Tests: `tests/test_amsi.py` — 38 checks, pure and runnable on non-Windows CI,
plus a live provider round trip opt-in behind `VALKYRIE_TEST_LIVE_AMSI=1`
(opt-in per the host-safety rule, since a conviction writes to the AV's history).
