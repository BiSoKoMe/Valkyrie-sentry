# Valkyrie test plan — what to test, in what order, and why

Written 2026-07-28 from **measured** coverage, not intuition. The ordering is
deliberate: each tier is worthless until the tier above it is done.

The premise, established by audit: Valkyrie's code craft is good (median function
8 lines, zero bare `except:`, 35 ADRs, one coherent telemetry spine). Its
*verification* is the weak half — and verification, not craft, is what separates
this from commercial security software. CrowdStrike's July 2024 outage and Palo
Alto's CVE-2024-3400 are proof that commercial vendors do not out-code us; they
out-*verify* us. This plan closes that specific gap.

## Baseline (measured 2026-07-28)

Line coverage over the 50 network-safe suites: **59%** (11,818 statements).

> Understated for `mac_randomizer`, `firewall`, `multihop`, and `threat_intel` —
> their test files were excluded from this run under the host-safety rule
> (`test_firewall.py` installs real `netsh` rules and has taken this machine
> offline before). Re-measure those inside the VM, not here.

Genuinely at **0%**, with no test file at all:

| Module | Stmts | Why it matters |
|---|---:|---|
| `self_test.py` | 140 | The subsystem whose entire job is verifying protection works — itself unverified |
| `fingerprint.py` | 139 | Pillar-3 (randomizer) component |
| `resolver.py` | 168 | Local recursive resolver |
| `tls_addon.py` | 275 | TLS interception path |
| `__main__.py` | 855 | Contains the 1,329-line `main()` |
| `doh_detector.py` | 64 | DoH-bypass evasion detection |
| `wireguard.py` / `ui.py` | 165 | Config generation, CLI surface |

Substantial code under 50%: `tls_inspector` 16%, `telemetry_killer` 21%,
`process_watcher` 23%, **`dns_interceptor` 33%**, `meeting_mode` 35%,
`web/server` 41%, `blocklist` 45%, `fleet/agent` 45%.

---

## Tier 0 — Make the results mean something ✅ DONE (2026-07-29)

**Nothing below this line counted until this was done.** A test that executed
zero assertions printed `ALL PASSED`, exited 0, and the runner counted it as a
pass ([run_tests.py](../tests/run_tests.py) judged on exit code alone; 34 files
used the "no failures recorded → ALL PASSED" pattern; **no file asserted that a
minimum number of checks actually ran**).

Shipped:

1. **[tests/harness.py](../tests/harness.py)** — `Checks` counts executed
   assertions. Zero checks ⇒ **fail**, not pass. Declared `expect_min` ⇒ a check
   that silently disappears fails. The harness self-tests these properties.
2. **Real skip semantics.** Skips exit **77**; the runner reports four outcomes —
   `passed · failed · skipped · vacuous` — and never folds a skip into "passed."
3. **Vacuous detection for all 58 files without rewriting them.** Harness-based
   files report counts directly; legacy files are judged on whether their output
   shows any evidence a check ran. Proven: a probe test that exits 0 having
   asserted nothing is reported `VOID` and returns exit **1**.
4. **Coverage floor in CI** at 55% against the measured 59%, as a ratchet.
5. **Linters promoted from advisory to gating** — the lint job was
   `continue-on-error: true`, so a red lint blocked nothing. Added **bandit** at
   HIGH/HIGH, which gates today rather than starting non-gating.

*Done when: deleting the body of any single test causes a visible CI failure.* —
verified.

### What Tier 0 uncovered on the way

Making results honest immediately surfaced four defects that a green suite had
been hiding. This is the argument for the tier, in miniature:

- **A real product bug.** [`IntelligenceMemory.check()`](../valkyrie/intelligence/memory.py)
  returned `None` for *every* verdict on a popular domain, though its own comment
  said the guard was for `bad` only. The ADR 0033 FP fix had killed the `good`
  fast path for exactly the highest-traffic domains, so every lookup re-ran the
  full pipeline. Not a safety hole — it failed toward more analysis, never less —
  but it silently negated the cache where it mattered most. **Fixed**; the two
  failing checks in `test_intelligence` now pass (32/32), and the popular-domain
  FP protection still holds.
- **The documented invocation did not work.** `python tests/run_tests.py` killed
  **7 suites** with `UnicodeEncodeError` — Windows consoles default to cp1252 and
  the tests print arrows and box-drawing characters. `PYTHONUTF8=1` had been
  applied by hand as a workaround instead of fixed. The runner now forces UTF-8
  in the child process.
- **A report wearing a test's filename.** `test_scanner_accuracy.py` computed
  precision/recall and then `return 0` unconditionally — it could measure 0%
  recall and still pass. Now gated: FP == 0, recall ≥ 0.85, precision ≥ 0.95
  (measured 1.000 / 0.933 / 0 FP).
- **Our own detector tripped a Trojan-Source scanner.** `behavior_score._BIDI`
  held the bidi control characters *literally* — the same codepoints it exists to
  detect, embedded raw in source, making its own diff untrustworthy. Rewritten as
  `\uXXXX` escapes; codepoints byte-identical.

- **A nondeterministic test — still open.** `test_playbooks.py` failed **8 runs
  in a row**, then passed **18 in a row**, on the same commit, and it fails at
  `HEAD` too, so it predates this work. Section [4]'s response was verified to
  land in 0.00s when probed directly, so the 3s polling deadlines were not the
  cause — they are now `_WAIT = 10.0`, which removes a false-failure class but
  is **not a fix**, because the root cause is unidentified. A test that answers
  differently on identical input is as useless as one that asserts nothing.
  Treat this as open until the mechanism is found.

Remaining known gaps, deliberately not closed here: `shell=True` in
[`edr/response.py`](../valkyrie/edr/response.py) is safe by construction (fixed
literals, no interpolation) and is annotated `# nosec B602` rather than
refactored, because that path installs live firewall rules and cannot be
exercised safely outside a VM — see tier 4. The medium bandit findings (B104
bind-all, B310 `urlopen`, B314 XML parsing) are triage items for tier 2; the
XML one is the most interesting, since `etw/wineventlog.py` parses
attacker-influenced event XML with stdlib ElementTree.

## Tier 1 — Test what actually breaks users

For this product a **false positive is worse than a false negative**. A missed
threat is one machine at ambient risk; an FP means DNS returns `0.0.0.0`, the
domain is dead, the user's bank or WiFi stops working. That has already happened
here twice — the world-banks ML false-positive, and the query-burst class that
sinkholed microsoft/paypal/bing/live/linkedin.

`dns_interceptor.py` is the decision core, is **33% covered**, and is where both
incidents lived. It is the single highest-value target in the repo.

6. **Full decision-matrix tests** for `_decide`: every ordered stage (user rules
   → intel → known-good → scanner → blocklist → behavioural → anomaly), each
   precedence relationship pinned, including the regression that hard blocks must
   beat the known-good fast path.
7. **A standing benign corpus.** The top ~1,000 real domains — banks, ccTLDs,
   CDNs, government, foreign-language sites — asserted **never blocked**, run as
   a gate. This is the test that would have caught both past outages, and it is
   the single most valuable test in this document.
8. **Persistence-of-verdict tests.** An FP must not be writable into
   `intel_memory` as a permanent `bad` verdict; prove the popular-domain floor
   and the self-heal purge both hold.
9. **`web/server.py` (41%)** — auth on every state-changing route, and the
   token gate on each responder. Untested auth is how a local API becomes a
   local privilege escalation.

*Done when:* the benign corpus gate runs in CI and `dns_interceptor` is >80%.

## Tier 2 — Adversarial input (the CrowdStrike lesson, literally)

CrowdStrike bricked 8.5M machines because a **content parser read out of bounds
on a malformed input file**. Valkyrie parses plenty of hostile-controlled data
and has *no* malformed-input tests anywhere.

10. **Fuzz every parser** with `hypothesis` or `atheris`, asserting only "never
    raises, never hangs, never allocates unboundedly":
    - `etw/wineventlog.parse_event_xml` — parses attacker-influenced event XML
    - `site_analyzer` HTML/JS scoring — parses *hostile web pages* by design
    - `siem.py` CEF/JSON serializer — malformed fields must not corrupt a record
    - `kernel_bridge.record_to_event` — parses a **kernel** ring buffer
    - DNS wire parsing in `dns_interceptor`
    - `config.py` / rules / playbooks YAML loaders
11. **Property-based tests for the pure classifiers.** `classify_amsi_result`,
    `classify_dga`, `shannon_entropy`, `behavior_score`: invariants like
    monotonicity, idempotence, and "never returns malware for empty input."
12. **Resource-exhaustion tests.** Bounded queues drop rather than grow, the LRU
    caches stay bounded, and no unbounded read exists on a file path an attacker
    can influence.

*Done when:* a fuzz job runs in CI and every parser survives 10k malformed inputs.

## Tier 3 — The unverified subsystems

13. **`self_test.py` (0%)** — first, because it is the component that tells the
    user "you are protected." If it can report healthy while broken, every other
    guarantee in the product is void.
14. **`fingerprint.py` (0%)** — a whole pillar-3 capability with no test.
15. **`resolver.py` (0%)**, **`tls_addon.py` (0%)**, `doh_detector.py` (0%).
16. **`__main__.py` (0%, 855 stmts)** — do **not** write tests for the
    1,329-line `main()`. Extract the wiring into testable composition functions
    first; the god function is the bug. Same for the 524-line `create_app()`.
17. **`telemetry_killer.py` (21%)** — currently skips entirely without admin.
    Test the pure registry-diff/restore logic without elevation, so the skip
    stops hiding the whole module.

## Tier 4 — Ground truth (VM only, never this host)

Everything above measures Valkyrie against itself. This tier is the only one that
measures it against reality.

18. **Confirm AMSI** — self-test must return `confirmed` in a Defender-active VM
    (it is legitimately `inconclusive` here; see [redteam/README.md](../redteam/README.md)).
19. **Build, test-sign, and load the kernel driver.** 795 lines of C that has
    never been compiled. Every prevention claim is hypothetical until it boots
    and survives. `driver/README.md` has Build/Sign/Load/Validate.
20. **Run the Atomic Red Team pass** against a live agent (`redteam/`). Expect a
    *worse* number than the in-repo harness. **That worse number is the real
    one** and the only detection rate worth optimizing.
21. **Re-measure `firewall` / `mac_randomizer` / `multihop` coverage** in the VM,
    where the host-safety exclusions do not apply.

## Tier 5 — What no test suite can give you

22. **Adversarial review.** Every test here was written by the same author as the
    code, which is the exact weakness in the efficacy corpus (100% recall on
    inputs we chose ourselves). Get someone — or a separate model instance with
    no context — to attack the code with intent to break it. This is the closest
    available substitute for the hostile peer review commercial vendors get by
    having a payroll.

---

## Priority if you only do three things

1. **Tier 0.1–0.2** — stop tests passing while testing nothing. Half a day, and
   until it is done every number in this repo is unreliable, including the ones
   reported today.
2. **Tier 1.7** — the 1,000-domain benign corpus gate. Would have caught both
   real outages this project has actually had.
3. **Tier 4.20** — the Atomic Red Team detonation. The only honest answer to
   "does Valkyrie work."
