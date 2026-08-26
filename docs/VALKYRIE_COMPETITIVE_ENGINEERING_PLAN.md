# Valkyrie Competitive Engineering Plan — the honest path to enterprise-ready

Written as the founding engineer would: what is winnable, what is not, the math
behind both, and the sequenced build that gets Valkyrie to "a billion-dollar
company runs it with no complaint." No fake parity. The goal is not to look like
CrowdStrike; it is to be undeniable at the one thing CrowdStrike structurally
cannot do.

---

## 1. The honest math: what a solo dev cannot buy, ever

Three walls are made of money and headcount, not code. Pretending to scale them
is how the project dies chasing a number it can't reach.

| Incumbent moat | What it costs | Reachable solo? |
|---|---|---|
| Cross-fleet telemetry (CrowdStrike Threat Graph: 2.5T events/week) | millions of endpoints reporting in | **No.** Network effect can't be self-generated. |
| EV code-signing + Microsoft kernel attestation | EV cert (~$300–600/yr) + attestation + a business identity + CI signing | **Partly.** The cert is affordable; the trust/process is the work. |
| 24/7 SOC + MDR + contractual autonomy underwriting | a staffed operations centre | **No.** A person can't be a SOC. |
| 2,900+ ML models over triple-density telemetry (PANW XSIAM) | a data-science org + the telemetry to train on | **No.** |

**Conclusion, quantified:** on the axes the incumbents compete on, Valkyrie's
ceiling is a small fraction of theirs, and effort spent there converts to ~0
competitive gain. This is not defeatism — it is where NOT to spend the finite
hours of one engineer.

## 2. The winnable game: the sovereign endpoint, and NYX as its proof

Every one of the ten majors is, mechanically, a telemetry-exfiltration business
(see `docs/VENDOR_ARCHITECTURE_2026.md`). CrowdStrike's product *is* the pipe to
their cloud; Zscaler's *is* terminating your TLS; Microsoft's edge *is* already
having your data. **None of them can offer detection that never leaves the
machine — their architecture forbids it.** That is the single axis where the
incumbents cannot follow, and it is exactly where NYX lives.

So the strategy is not "Valkyrie the smaller EDR." It is:

> **Valkyrie is the platform. NYX is the identity. The promise is: world-class
> privacy protection whose data never leaves your machine — provably.**

The EDR is real and honest, but it is the *supporting* capability ("also watches
for malware, on-agent, no cloud"), not the headline that invites a losing
CrowdStrike comparison.

### The NYX math (why it can actually be best-in-class)

NYX's current measured state (`tests/nyx_battery.py`): **66/69 defended (96%),
0/19 false positives.** Unlike detection rate, this bar is *reachable to 100%*
because it does not need fleet scale — it needs coverage of a finite, knowable
set of tracking/fingerprinting/exfil techniques, and a hard no-false-positive
guard. That is a solvable engineering problem, not a money problem. **NYX is the
one scoreboard where "perfect" is a legitimate target.**

## 3. The enterprise-readiness bar — what "no complaint" actually means

"A billion-dollar company runs it with no complaint" decomposes into a checklist
that has almost nothing to do with detection percentage:

| # | Requirement | Current state | Priority |
|---|---|---|---|
| 1 | **Never harms the host** (network, files, boot) | DNS strand FIXED in logic (`host_safety.py`, 25 checks); firewall isolate/restore snapshots exist; OS shim + full wiring pending | **P0 — done first** |
| 2 | **NYX is undeniable** (→100%, provable no-FP, a "caught what nothing else can" story) | 96% / 0-FP; 3 named gaps queued | **P0** |
| 3 | **Stability** — no crashes, graceful degradation, self-heal | startup-deafness open (`valkyrie_startup_deafness`); watchdogs partial | P1 |
| 4 | **Trustworthy reporting** — no report can lie | DONE: evidence librarian (ADR 0054) | ✅ |
| 5 | **Clean install/uninstall, no orphaned state** | Sysmon PPL + DNS strand lessons show gaps | P1 |
| 6 | **Honest capability labeling** — no fake parity | strong culture already (ADRs, memory) | ✅ ongoing |
| 7 | **Signed kernel driver** (or honest "userland-only") | compiled, `/W4 /WX` clean, PREfast 0, UNSIGNED | P2 (business step) |
| 8 | **A crisp, safe UI + one-click value** | Electron installer builds; UX not audited | P2 |

The order is deliberate: **#1 and #2 are the product.** Everything else is
supporting. A privacy tool that is safe and best-in-class at privacy is
shippable to friendly beta users even with an unsigned driver and a
Sysmon-dependent EDR — *if it is honest about those*.

## 4. The kernel / driver: the honest position

`driver/valkyrie_km/` compiles clean (`/W4 /WX`, PREfast 0 warnings, ~26 KB
`.sys`) and provides ETW-independent process-notify telemetry — the one source a
consumer AV's ELAM driver cannot strip the way it stripped Sysmon on this very
host (`valkyrie_sysmon_ppl_deadlock`). But it is **unsigned and must never be
loaded.** Loading needs an EV cert + Microsoft attestation — a business/legal
step, not an engineering one.

**Engineering honest path:** treat the driver as *ready-but-dormant*. Ship
userland (ETW/Sysmon/4688) as the live sensor, label it as such, and make the
driver a documented "available on signing." Do NOT claim kernel-grade tamper
resistance until the driver is signed and loaded. That honesty is itself an
enterprise-trust asset.

## 5. The detection math, told honestly

The live EDR number was never "23%." Reclassified through the evidence librarian
(the never-executed, sensor-off, and single-VM techniques removed from the
denominator, plus the measurement fixes of 2026-08-24): **~22/26 validly
measurable ≈ 85%, projected, pending one clean run.** The suppressors were three
measurement bugs (burst window, eval window, db_coverage), now fixed. The last
one — per-technique polling that drops real-time hits under load — is fixed in
`attribute.py` and needs wiring into the PowerShell harness.

**The number to publish is not a headline percentage.** It is the evidence
librarian's honest scorecard: what was validly measured, what was detected, what
remains unmeasured and *why*. Publishing that — misses and all — is a trust
weapon none of the incumbents deploy, because they can't afford the honesty.

## 6. The sequenced build (the actual work order)

1. **P0 · Host safety.** `host_safety.py` logic ✅. Next: the reviewed OS shim
   (`dns_os.py`), supervised activation, extend the invariant to firewall/file
   operations. *Nothing ships until Valkyrie cannot harm the host.*
2. **P0 · NYX to world-class.** Close the 3 named battery gaps; add the Tier-3
   headless-browser-through-live-proxy test (CreepJS/browserleaks); build the
   "here is what NYX caught that your browser and your VPN did not" demo. Drive
   the battery to 100% with the FP guard held.
3. **P1 · Stability.** Fix startup-deafness (async warm-up blocking the loop);
   make every subsystem fail-degraded, never fail-dead.
4. **P1 · Clean lifecycle.** Install/uninstall leaves zero orphaned state
   (DNS, firewall, Sysmon, tasks) — audited, tested.
5. **P1 · Trustworthy live number.** Wire `attribute.py` into the harness; one
   clean Tier B; publish the librarian scorecard.
6. **P2 · Driver signing, UI audit, beta program** (5 friendly users, not
   "clients"; real feedback before a user base).

## 7. The one principle that makes it enterprise-grade

Incumbents earn trust with a logo and a support contract. Valkyrie has neither,
so it must earn trust *structurally*: it cannot harm the host, it cannot lie in
a report, it cannot claim a capability it has not proven. That triad —
`host_safety` + the evidence librarian + no-fake-parity — is not overhead. For a
solo tool asking a billion-dollar company to run it, **it is the moat.**
