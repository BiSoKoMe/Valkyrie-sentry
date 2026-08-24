# ADR 0041 — Closing the measured Tier A gaps: recon-burst, service-stop, tool-transfer, credential-store, and path-level blocking

Date: 2026-08-04 · Status: accepted

## Context

`redteam/evaluation/` (the 40-technique, 8-tactic Atomic Red Team catalog) scored
Valkyrie at **25/40 (62.5%)** on Tier A. That report did not just give a number —
`root_cause.py` names a concrete code fix for every miss. This ADR executes the
subset that needs no new infrastructure, plus two network-side items from
`docs/GAP_ANALYSIS.md`.

The weakest tactic by far was **Discovery at 17% (1/6)**, and the report is
explicit about *why* it is hard: `whoami`, `systeminfo`, `tasklist`, `net view`
and `net user` are indistinguishable from routine administration. Adding a
MEDIUM-severity rule for any one of them would trade a real detection gap for a
real false-positive generator — the wrong trade for this product, and one this
codebase has already been burned by (the `net-user-add` overbroad rule, fixed
during the previous evaluation cycle).

## Decision

### 1. Reconnaissance burst — breadth, not order (Discovery 17% → 83%)

A single discovery command still raises **nothing**, deliberately.
`process_telemetry.classify_discovery` attaches an INFO-severity
`discovery_command` label and a technique id, and stops there. Detection comes
from **breadth**: `behavioral_sequences.py` gains a `reconnaissance-burst` rule
that fires (MEDIUM) only when **≥3 DISTINCT** discovery techniques appear on one
process lineage within 120s.

This required a genuinely new capability in the sequence engine, which until now
could only express *order* (A then B). `Step.min_distinct` (default 1 — every
existing rule's behaviour is byte-identical) makes a step accumulate distinct
matching signals before advancing, so a single-step rule with `min_distinct=3`
expresses "several different weak signals, any order." A real recon sweep runs
these commands in whatever order the operator reaches for them, not a fixed
shape, so encoding it as an ordered pair would have been wrong.

**The delivery half matters as much as the logic.** These commands exit in
milliseconds, so the 2s psutil poller loses the race — the burst would have been
dead on arrival if it depended on that. `etw/sysmon.py` EID 1 (which also backs
`native_process.py`'s Security/4688 sensor) now runs `classify_discovery` too,
and lets a discovery-labeled event through its `SEV_LOW` gate. The event stays
INFO/`observed` and is dropped by the EDR's own severity gate; it is routed to
the sequence engine *before* that gate purely so the burst combiner can see it.
Same lesson as the earlier "run the full classifier stack on EID 1" fix: correct
logic behind a dead delivery path is not detection.

### 2. Security-service stop / disable (T1489) — Impact 67% → 100%

Two rules (`service-stop-security`, `service-disable-security`), because "stop"
(`sc`/`net`/`Stop-Service`) and "disabled" (`sc config` / `Set-Service
-StartupType Disabled`) are different command shapes. Each requires **both** the
verb (`cmd_all`) and a security-relevant service name (`cmd_any`), so
`sc stop Spooler` and `sc query WinDefend` both stay clear — regression controls
in `tests/test_behavioral_rules.py`.

The Tier B test reference had to change with it: a live run must rename a
throwaway service *into* the watched set, because a service literally named
`DecoySecurityService` matches nothing by design. `root_cause.py` additionally
proposes a `Win32_Service` artifact-at-rest check; that remains **unbuilt**, and
is what would cover a service stopped with no command line at all (Services MMC,
a direct API call) — these command-shape rules cannot see that.

### 3. Lateral tool transfer (T1570)

One rule: a UNC path (`\\`) **and** a well-known administrative share
(`C$`/`D$`/`ADMIN$`/`IPC$`). MEDIUM, not HIGH — legitimate IT admin work copies
to admin shares constantly. A UNC copy to an ordinary file-server share does not
match, which is the FP boundary. The single-VM caveat from the original report
stands unchanged: a self-target run proves the command shape is recognised, not
that cross-host movement is detected.

### 4. Browser credential-store watch (T1555.003)

New `valkyrie/browser_cred_watch.py`. The old scoring path was a command-line
rule, which only ever sees the *launch command* — useless against a compiled
stealer that opens `Login Data` directly with nothing revealing on its command
line. The new collector polls open file **handles** (the same `psutil`
technique the ransomware shield already uses for suspect attribution) against
the known Chrome/Edge/Brave/Vivaldi/Firefox credential-store paths, enumerated
across every real user profile under `C:\Users` (the engine runs as LocalSystem;
`~` would be the service profile — the same trap already fixed in `decoys.py`
and `persistence_telemetry.py`).

HIGH severity with no corroboration required, which is a deliberate exception to
the "no single weak signal fires" rule: the owning browser processes are
explicitly excluded, and a **non-browser** process holding a browser's password
store open has essentially no innocent explanation.

### 5. Threat-intel feeds default ON

`USE_EXTERNAL_LISTS` flips `False → True`. Feodo/URLhaus/ThreatFox and the
tracker-blocklist refresh were silent no-ops for anyone who did not know to pass
`--download-lists`. A security product whose live threat intelligence is off by
default understates its own real-world detection, and that is not an honest
default. Matching remains 100% local either way — this flag only controls
whether the periodic *feed fetch* happens; no indicator, domain, or IP has ever
left the machine and none does now. New `--no-download-lists` is the per-run opt
out; `firewall.start()` now honours the same resolved policy instead of keying
on the force-flag alone.

### 6. Path-level (full-URL) blocking via the TLS inspector

`threat_intel.py` gains a third indicator kind, `url`, alongside `ip` and
`domain` — the extension seam ADR 0015 documented and left open. `normalize_url`
canonicalises both sides to `host[:port]/path[?query]` (scheme-, case-, default-
port-, fragment- and trailing-slash-insensitive; **query preserved**, since for
malware distribution it frequently selects the payload), behind the same guard
rails as every other indicator — a poisoned feed can never make Valkyrie block
loopback, private, reserved, or dotless hosts.

`match_url` is **exact**, not prefix or parent-based, and that is the whole
point: malware is overwhelmingly hosted on compromised-but-otherwise-legitimate
sites, so a hit on `example.com/wp/uploads/x.exe` says nothing about
`example.com`. Blocking the parent domain from a URL indicator would take the
legitimate site down with it. Enforced at exactly one seam — `tls_addon.py`,
checked *before* the domain blocklist because it is the more specific verdict.
DNS never sees a path, so this indicator kind is unreachable without TLS
inspection, and the code says so rather than implying broader coverage.

## Consequences

**Measured, not asserted:**

| | Before | After |
|---|---:|---:|
| Red-team Tier A | 25/40 (62.5%) | **32/40 (80.0%)** |
| — Discovery | 1/6 (17%) | **5/6 (83%)** |
| — Impact | 2/3 (67%) | **3/3 (100%)** |
| — Credential Access | 1/4 (25%) | **2/4 (50%)** |
| — Lateral Movement | 1/3 (33%) | **2/3 (67%)** |
| Efficacy gate (recall / FPR) | 100% / 0% | **100% / 0%** (held) |
| Shipped IOA rules | 35 | 38 |
| Named sequence IOAs | 5 | 6 |

**Honest boundaries — unchanged by this work:**

- Tier A is still **classifier-input replay**, not a live attack. It cannot
  measure real execution, latency, or aggregate FP rate, and every such field in
  the report is `null` with a reason. **Tier B has still never been run**; that
  number will be worse and it is the one that counts.
- The Discovery detections are scored as **burst contributors, not standalone
  alerts**. Every affected record's `notes` says so explicitly, so no row can be
  read in isolation as "running this one command raises an alert."
- The credential-store watch is a **5s poll, not a filesystem minifilter**. A
  stealer that opens, copies, and closes the handle inside one interval is
  missed. That gap closes only with the kernel driver (ADR 0026), which has
  still never been compiled.
- Real-time discovery delivery depends on **Sysmon or Security/4688 auditing**.
  Without either, the burst falls back to the racy 2s poller and will usually
  lose — the same conditional that has always applied to command-line techniques.
- URL blocking requires the **TLS inspector** (opt-in, needs the CA installed).
  Without it, URLhaus coverage remains domain-level only.

## Alternatives rejected

- **A rule per discovery command.** Named in the evaluation's own root-cause
  text as the wrong trade: it converts a detection gap into a false-positive
  generator. Rejected on the project's standing precision-over-aggression rule.
- **Raising `whoami-priv` to MEDIUM** so it fires alone. Same objection; the
  existing LOW severity was chosen deliberately and is left alone.
- **Prefix/parent matching for URL indicators.** Would block whole legitimate
  domains off a single compromised path — the exact false positive the feature
  exists to avoid.
- **A pure-entropy or blocklist-shaped URL check.** Same reasoning as ADR 0024's
  DGA decision: corroboration or exactness, never a broad heuristic on a
  user-visible blocking path.
