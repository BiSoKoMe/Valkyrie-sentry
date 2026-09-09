# Valkyrie, NYX and Aegis: engineering roadmap

Started: 2026-09-05. Final review: 2026-09-06. Source baseline: `db38d7c`. Status: proposed implementation plan, based on source review and existing evidence. This review did not run the product, replay attacks or validate the installed service.

## The decision

Build a trustworthy security and privacy product for **one Windows PC, managed locally**. The owner confirmed that **Aegis should provide Cortex XDR-style investigation and correlation**. The first release should make a small set of defensible promises and prove them through the installed application.

The suite is Valkyrie. Inside it, Valkyrie Endpoint observes and enforces, NYX protects privacy, and Aegis investigates. Keep one engine, one evidence model, one response authority and one console. The component names describe responsibilities, not three separate agents competing for control.

The credible differentiator is local correlation of process behavior, network consequences and privacy disclosures, with understandable evidence and bounded response authority. Novelty and comparative benefit are hypotheses to test. An offline runtime alone does not establish superiority: CrowdStrike documents offline protection in [Falcon Prevent](https://www.crowdstrike.com/wp-content/uploads/2024/09/crowdstrike-falcon-prevent-data-sheet.pdf).

For implementation priority, this roadmap supersedes the aspirational claims and projected percentages in `VALKYRIE_COMPETITIVE_ENGINEERING_PLAN.md`. Historical experiment reports remain evidence for their specific versions and workloads. A fixed-corpus pass does not establish perfect privacy or commercial EDR parity.

## What exists, and what still needs proof

- **A substantial local core exists.** `valkyrie/edr/engine.py:98` coordinates telemetry, incidents and investigation; `valkyrie/edr/schema.py:167` defines incidents. Reuse this work.
- **There are two evidence representations already.** `valkyrie/telemetry.py:87` defines sensor-facing `TelemetryEvent`; `valkyrie/edr/detection_v2.py:70` defines `CanonicalEvent`. Document and version their adapter rather than inventing a third envelope.
- **The newer architecture is deliberately in shadow mode.** `valkyrie/edr/engine.py:154` says it cannot originate incidents or authorize enforcement. Branding changes must preserve that restriction.
- **NYX has real inspection and rewrite paths.** See `valkyrie/nyx.py:328`, `:661`, `:707` and `valkyrie/tls_addon.py:352`. The reliability report records three 15-minute live proxy/browser runs, then a later device-ID leak and six reruns after a fix. This is useful evidence and a reason to expand testing, not a universal guarantee. See `BETA_1_NYX_RELIABILITY.md:12` and `:209`.
- **Telemetry has live component evidence.** `BETA_0_5_TELEMETRY_RELIABILITY.md:918` records three fresh-runner 25-minute qualifications. Reproduce through the packaged service before treating it as installed-product reliability.
- **Current Aegis is privacy exposure reasoning.** `valkyrie/aegis_bridge.py:111`, `aegis_exposure.py:217` and `aegis_planner.py:59` implement exposure/linkability reasoning and synthetic actuator planning. This is different from the requested investigation product.
- **Fused reasoning has narrow live evidence.** `PLATFORM_BETA3_FUSED_RELIABILITY.md:5` records 285 visits over 10 minutes without cross-subject contamination. At `:29`, it explicitly excludes production-engine deployment and new mitigation efficacy.
- **EDR efficacy is not one headline percentage.** `LIVE_FIRE_EVALUATION.md:332` distinguishes a historical union of detections from repeatable runs. The September 4 fix improved repeatability, but `:382` rejects turning 35/73 into a detection rate because execution and visibility denominators differ. At `:414`, real desktop false-positive rate remains unmeasured.
- **Causal authority is an experiment.** `adr/0059-causal-authority-reflex.md:5` and `browser_context.py:8` constrain the mechanism: no reliable browser-to-Windows-PID identity and no general browser request blocking. Synthetic grant verification latency excludes browser, transport and enforcement.
- **Kernel readiness is unresolved, not shipped.** `driver/README.md:9` reports no build/sign/load evidence, while older planning documents claim a clean build. Resolve that conflict with a reproducible build and artifact evidence. No deployed driver capability belongs in the release claim until independently demonstrated.

These findings are based on local files. Historical CI results were read from reports, not re-fetched or independently reproduced during this planning task.

## Immediate release blockers

### P0. Local control authorization

`valkyrie/web/server.py:1392` returns the control token to a loopback caller. `_origin_is_local()` at `:438` accepts absent Origin, and the control/EDR guards at `:457` and `:471` accept that token. A native local process can satisfy those checks without proving its Windows user or integrity level. The installer configures a privileged service with the web API enabled (`installer/payload/service-install.ps1:54`).

This is a source-level authorization gap. In an elevated deployment, an otherwise unprivileged local caller may reach privileged controls, subject to the individual responder's checks and availability. This review did not demonstrate an exploit or arbitrary SYSTEM code execution.

Required design: remove anonymous credential bootstrap; authenticate local control through Windows security primitives. Keep routine viewing unprivileged. Use an ACL-restricted named-pipe broker that checks caller identity and integrity, exposes typed capabilities, and requires an authorized elevated session for manual privileged controls and policy changes. Broker-owned lease expiry and recovery remain unattended; bounded automated responses require previously authorized policy and independently checked evidence. A pipe name or user SID alone is not proof that an application is trustworthy. Enforce authority at the broker, not in renderer text or caller-supplied `operator` values.

Exit gate: a separate standard-user process, another logged-in user, a remote browser origin and a replayed/expired session cannot obtain privileged authority. An authorized operator can still perform approved actions. Exercise with a non-mutating fake responder before real VM-only control tests.

### P0. Response success, leases and crash recovery

Built-in responders return `succeeded` (`valkyrie/edr/response.py:163`, `:400`). The manager invokes its post-enforcement accounting only for `ok`, `success`, `completed` at `:916`; expiry processing uses the same incompatible set at `:877`. Successful actions can skip lease and response-budget registration, and successful reversals can remain due. The fake responder in `tests/test_response_gating.py:37` defaults to `ok`, which obscures the contract mismatch.

Normalize on the existing response vocabulary at the adapter boundary. Add contract tests using real responder classes with mocked OS executors. Separate requested, authorized, applied, verified, failed and reverted states; dry-run is never applied. Persist action intent and enough rollback metadata before changing the host, then reconcile incomplete transactions after restart. Recovery must not depend on a healthy web UI or a live analytics thread.

Exit gate: every successful reversible action obtains its lease and budget record; expiry restores exactly the state Valkyrie owns and stops retrying after verified reversal. Test duplicate requests, partial apply, failed persistence, process death at each state transition, clock changes and recovery after reboot. Do not remove another application's firewall rules or overwrite a newer operator change.

### P0. Windows release evidence

The Windows test job remains advisory (`.github/workflows/tests.yml:80`). The executable workflow publishes tagged artifacts without depending on the test workflow (`build-windows-exe.yml:25`, `:80`). The coverage job runs files directly and ignores failures (`tests.yml:221`), unlike the runner's pytest-aware routing.

Classify pure, integration, privileged-host and VM-only tests explicitly. Make the supported Windows checks required, include Electron and installer changes in triggers, and run the appropriate test entry points under coverage. Package and test the same artifact digest before publication. Deliberately break a required test and verify publication is impossible. Keep destructive and networking tests on disposable environments.

## Component responsibilities

### Valkyrie Endpoint: observe and enforce

Own process lifetime identity, process ancestry, Windows event/ETW/Sysmon adapters, network and DNS attribution, persistence changes, sensor health, the DNS enforcement path and the privileged response broker. Integrate existing OS antimalware verdicts as attributed evidence. Continue to coexist with Windows' existing protection.

Start with supported Windows 11 x64 builds on a declared compatibility matrix. Windows 10 and ARM64 require separate support decisions and evidence. Keep an honest user-mode release; a custom kernel driver is a later track with its own threat model and release gates.

Priority engineering:

1. Carry boot/session identity, process creation time, collector identity, event time, ingest time, sequence/gap information and provenance confidence through normalization. Preserve unknown identity explicitly.
2. Build readiness from subscription readiness and backlog progress, not only process liveness. Show stalled, behind, degraded and unavailable sensors with reason and last-good time.
3. Bound queues and expose drops at each boundary. `eventbus.py` currently calls subscribers synchronously and swallows subscriber exceptions; isolate expensive work and count errors without silently claiming delivery. The Windows reader bookmark is memory-only (`etw/wineventlog.py:171`), and a fresh reader advances to the latest event (`:240`). Add bounded durable ingest/checkpoints, replay deduplication and event-log-clear detection for persistent mode; expose the unrecoverable interval in zero-log mode. Define whether acknowledgment means queued or durably ingested.
4. Keep DNS decision work short and deterministic. Disk I/O, graph traversal, signature scans and enrichment belong on bounded workers with documented fallback behavior.
5. Use different failure behavior for different failures. Broken infrastructure must trigger recovery of owned network state; ambiguous threat evidence must suppress new autonomous action. Restoring network availability is separate from overriding an explicit user block.
6. Improve detections from actual missed chains, not rule counts. Initial scope: suspicious script execution, persistence changes, credential-access signals where the sensor supports them, process-to-egress chains, ransomware-like behavior on disposable test data, and sensor tampering.

Before enabling process termination, close a specific identity gap: `edr/response.py:186` accepts a PID target and opens the current process at `:198` without checking it against the incident's original creation identity. Carry boot ID, PID and creation time/process GUID through authorization and revalidate immediately before the action. A stale incident must never act on a new process that reused the PID; missing identity requires refusal.

For each rule retain owner, version, needed sensors, evidence predicate, supported ATT&CK behaviors, benign counterexamples, known blind spots, test cases, and allowed responses. Do not classify an installer as safe solely because of its path, popularity or signature.

### NYX: privacy controls with measured visibility

Own disclosure inspection, privacy observations, site-scoped personas, browser context, consent/authority experiments, and the existing exposure/linkability research. Keep raw content out of general telemetry, incident text and exports.

The strongest product hypothesis is: **a local system can distinguish an intended disclosure from a suspicious consequence more accurately when it combines scoped user intent with endpoint provenance.** Test that against privacy-only and endpoint-only baselines. Do not claim that this idea has no prior art.

Priority engineering:

1. Replace silent bypasses with coverage states: inspected, protected, observed-only, unsupported, unattributed, oversized or failed. Same-site and missing-first-party exclusions at `nyx.py:342` are compatibility rules, not proof of authorization.
2. Preserve useful unattributed privacy metadata separately when `tls_addon.py:458` cannot obtain a PID. Never manufacture a process edge to make the graph appear complete.
3. Fix outcome semantics. URL rewrite failures at `tls_addon.py:397` can still reach `deceived`/`act_succeeded` reporting. Track each changed field and remaining disclosure, and verify delivery at a controlled receiver.
4. Replace sentence parsing in `nyx_graph.py:45` with structured records. Keep compatibility readers for historical records.
5. Partition personas by site/context so a stable replacement value does not become a global tracking identifier. Test consistency within a workflow and separation across unrelated sites.
6. Keep TLS interception explicitly opt-in, with a owned-CA/proxy lifecycle and tested cleanup. Pinned TLS, QUIC, application encryption and unsupported payloads require truthful capability states. Do not weaken certificate validation to improve coverage.
7. Keep browser grants experimental until authenticated binding and actual mediation are proven. A trusted click is a narrow input, not permission for every later action by that page. Test workers, frames, navigation, replay, expiry, destination changes and missing context.

NYX does not automatically falsify payment, identity, authentication or user-submitted form values. Supported sensitive workflows should preserve intended disclosure or require an explicit scoped policy, and unsupported behavior should be visible.

### Aegis: local investigation and correlation

Own incident formation, evidence timelines, causal investigation, hunting, triage, case state, decision explanations and response proposals. In the user's requested scope, this is a local investigation experience inspired by XDR. Full XDR across cloud, identity and email requires those data sources later. Palo Alto distinguishes [Cortex XDR](https://www.paloaltonetworks.com/cortex/cortex-xdr) from the broader [Cortex suite](https://www.paloaltonetworks.com/cortex); that distinction prevents an unbounded SOC-platform project.

Start Aegis as a facade over `EdrEngine`, existing incidents, the store and investigation APIs. Avoid an independent detector, database or response executor. Keep compromise likelihood, privacy sensitivity, user authority and sensor confidence as separate dimensions. A privacy observation alone is not a malware conviction.

The case view must answer: What happened? Which process instance caused which observable consequence? What is inferred? Which sensors were missing? Why was this grouped into one case? What action is permitted, what actually happened, and how is it reversed?

Priority engineering:

1. Stable case IDs, deterministic deduplication and explicit merge/split reasons. Keep unrelated users, process lifetimes and browser sessions apart.
2. Evidence-linked explanations with rule/policy versions and observed versus inferred edges. No invented causality or certainty score masquerading as calibrated probability.
3. Persist and reopen cases within the selected retention mode. Allow local search by time, process instance, destination, technique and action result.
4. Record triage outcome, narrowly scoped suppression with expiry, and why the operator dismissed a case. Do not poison detection baselines by treating every dismissal as trusted benign input.
5. Route every response through the same broker and authority checks as Valkyrie. Begin with dry-run and operator-approved reversible actions; defer autonomous destructive actions.
6. Keep AI explanation optional and outside the enforcement path. Default investigation must function without an LLM, subscription, network connection or uploading evidence.

## Architecture and migration

The supported flow is: **sensors and browser adapters -> privacy-safe normalization -> shared local evidence -> detection and correlation -> Aegis case -> policy/authority -> Valkyrie response broker -> verified outcome**. NYX supplies privacy evidence and executes only its specifically authorized privacy controls.

Define contracts before moving files:

- **Observation:** versioned sensor envelope and canonical mapping; stable identity, origin, timestamps, confidence, evidence references and coverage state.
- **Finding:** rule/version, supporting evidence, alternative explanation, confidence basis and scope. Distinguish compromise, disclosure and exposure inference.
- **Case:** stable ID, subject instances, ordered evidence, disposition and links to findings and responses.
- **Action request:** exact operation/target, authenticated principal, policy version, evidence references, idempotency key, preconditions and expiry.
- **Action result:** dry-run/applied/verified status, error class, owned changes, rollback state and timestamps. Outcome language must match the actual adapter result.

Use compatibility layers first. Wrap the old Aegis exposure modules under a NYX exposure service. Add NYX exposure routes while preserving `/api/aegis/status` and `/api/aegis/ledger` with their existing schema during migration. Put new investigation APIs in a versioned Aegis namespace. Do not change an exposure-ledger response into incident objects behind the same route.

Keep current `TelemetryEvent` ingestion and `CanonicalEvent` shadow behavior intact until a separately measured promotion. Replay the same corpus before and after migration: identical incident IDs, evidence, dispositions and authorized outcomes, with no duplicate cases. NYX failure must not stop endpoint collection or EDR.

Do not begin with a Rust rewrite. Keep Python orchestration and SQLite, use existing native acceleration, and move a specific measured bottleneck into native code only if it cannot meet its budget otherwise.

## Six phases with exit gates

Planning assumption: one experienced engineer working full time, access to disposable Windows VMs, and no major driver work. The 24-week sequence is a planning envelope, not a delivery promise. Add 25 to 50 percent contingency; part-time work can take roughly twice as long. Parallel help on Windows systems/security and test infrastructure reduces risk more than adding feature developers.

### Phase 0, weeks 1 to 2: contain the immediate trust gaps

Deliver immediate containment of anonymous privileged HTTP controls, the response-status/lease-accounting repair, required Windows release checks, test-safety classification and a versioned capability/evidence manifest. Keep privileged HTTP mutation unavailable in a distributable until the authenticated broker passes its gate. Design and test the broker contract here; complete service separation and durable crash recovery in Phase 1. Add Electron IPC sender validation, typed method/route allowlists and payload limits. Existing context isolation and sandboxing are strengths to preserve (`electron/src/main/main.js:91`); the generic `/api/` proxy at `:331` is too broad a capability boundary.

Gate: unauthorized callers cannot exercise the contained privileged HTTP path; real-adapter tests demonstrate correct lease accounting; a deliberately failed Windows test prevents artifact publication. The full P0 broker and recovery gates remain open until Phase 1. Do not call containment a hardened release.

### Phase 1, weeks 3 to 5: make the installed service recoverable

Deliver the authenticated privileged broker, least-privilege service boundaries, independent recovery, transactional DNS/firewall/proxy ownership, explicit protection states and reproducible installer artifacts. Close the full authorization and interrupted-response P0 gates before enabling broader enforcement. Update the Electron 31 dependency declaration to a currently supported release through staged compatibility work; audit the lockfile and shipped binary versions. Electron recommends current supported versions and validating IPC senders in its [security guidance](https://www.electronjs.org/docs/latest/tutorial/security).

Exercise the actual installer through boot, reboot, suspend/resume, network adapter changes, VPN use, offline operation, disk pressure, process crashes, upgrade and uninstall. Include coexistence with existing OS protection.

Gate: three fresh Windows installations complete the lifecycle suite with no stranded network settings, no orphaned owned CA/proxy/firewall state, and no changes to unrelated state. A 72-hour installed benign soak has no unexplained service exit or silent sensor failure.

### Phase 2, weeks 6 to 9: make endpoint evidence dependable

Deliver versioned event mapping, process-instance attribution tests, backlog/drop metrics, bounded worker isolation and a narrow set of tested detection chains. Preserve and extend the September 4 backlog fix instead of treating it as missing work.

Gate: repeat the declared chains three times through the same packaged release. Every promised chain must meet its predeclared evidence, detection, grouping and latency requirements on every valid trial, plus the verified response effect when prevention is claimed. Record experimental out-of-scope cases separately. Record execution success, expected sensor evidence, observed findings, grouping and latency per trial. A failed setup is not a detection miss; absent supported telemetry is a sensor failure and still fails that capability's release gate. Report exclusions separately.

### Phase 3, weeks 10 to 13: make NYX's promises testable

Deliver explicit coverage states, structured observations, accurate rewrite outcomes, site-scoped persona contracts and receiver-side verification. Expand the regression corpus using the already documented device-ID leak. Keep broad browser authority enforcement in research until mediation is demonstrated.

Gate: supported disclosure scenarios deliver only the permitted data; authorized login, payment-sandbox, upload and ordinary navigation workflows still succeed. Include independent holdouts, malformed payloads, browser updates and concurrent traffic. No raw test sentinel enters the engine's logs, databases, diagnostics or exports. Report every unsupported path.

### Phase 4, weeks 14 to 18: turn Aegis into a useful investigator

Deliver the compatibility migration, case view, evidence-linked timeline, local hunt, triage state and action history. Reuse existing APIs and backend logic. Improve the investigation UI around actual operator tasks rather than alert-count decoration.

Gate: a fresh operator can explain a supported incident, identify uncertainty, propose the narrow response and find the rollback result from the packaged UI. Replays with PID reuse, duplicates, late events and unrelated activity preserve correct case boundaries. Shadow detectors remain shadow until independently promoted.

### Phase 5, weeks 19 to 24: qualify a constrained local beta

Deliver signed user-mode packages, a configured update trust root, a reviewable verified update process, dependency inventory/SBOM, support diagnostics with redaction and a local recovery guide. `valkyrie/updater.py:40` currently has a blank release key and verifies only; provision real trust and a tested application/rollback process without inventing signing credentials.

Run seven days of realistic benign use in observation mode after the VM gates, then enable only individually qualified controls. Use multi-workload laboratory machines for longer reliability and interference tests. Obtain an independent security review of local IPC, privileges, update trust, privacy data flow and response recovery before wider distribution.

Gate: all P0 findings resolved, required exact-artifact checks pass, measured alert burden is acceptable, recovery is demonstrated and the release manifest contains only proven capabilities. Unknown results remain unknown. Release only the supported user-mode scope if driver evidence is absent.

## Proposed quantitative budgets

These are initial engineering targets, **not results achieved by this repository**. Freeze hardware, OS build, workload, feature flags and measurement definitions in Phase 0. Revise targets transparently after baseline measurement; do not move them silently to pass a release.

- **Sensor accounting:** every generated event in a controlled workload is consumed or accounted for by a reported gap/drop. No silent loss and no healthy status while a required sensor is stalled. Test 100 normalized events/s for 30 minutes and 1,000/s for a 60-second burst, then verify drain and recovery. These are engineering load tests, not estimates of real Windows event rates.
- **Detection latency:** proposed p95 at most 2 seconds and p99 at most 5 seconds from supported source event to visible incident under the baseline load. Report per sensor; a slower polling sensor is declared as such and cannot support a real-time claim. Measure the full path, not only `ingest_telemetry()` CPU time.
- **DNS cost:** proposed added local decision latency p95 at most 5 ms and p99 at most 20 ms, excluding upstream lookup time and reported alongside it. Separate cache hits, misses, error fallback and overload.
- **Resource cost:** on the frozen 4-core/16-GB reference machine, proposed idle mean CPU below 1 percent and normal-workload mean below 3 percent of total host CPU. Engine working set below 350 MB; engine plus open console below 700 MB. Report p95 and peaks separately, with optional TLS inspection clearly separated.
- **Retention:** proposed default recent telemetry up to 24 hours or 2 GB, whichever limit is reached first; show truncation and keep bounded case metadata separately. Establish actual rates before promising a retention duration. Zero-log mode is a distinct mode with explicit limits on post-restart investigation. Minimal recovery metadata needs a documented local exception or a tested alternative; never promise durable rollback while discarding all required state.
- **False alerts:** proposed local-beta target no more than one high-severity false incident per seven endpoint-days on at least 30 endpoint-days of declared benign workloads, with raw counts and uncertainty. Count incidents after documented deduplication, not selected alerts. This sample is not enough to claim population-level reliability.
- **False actions:** zero unintended disruptive actions in the complete qualification corpus. One such action blocks promotion of the affected control until root cause and rerun. Zero observed failures is not proof of a zero failure rate.
- **NYX correctness:** zero known raw-sentinel leakage and zero unauthorized modifications in supported positive/negative workflows. Report numerator, denominator, bypass rate and unsupported cases. Use held-out workloads; do not assert 100 percent real-world protection.
- **Recovery:** all lease expiry, interrupted installation/update and process-crash scenarios must restore owned state. At least three clean repetitions per supported lifecycle scenario; failures cannot be averaged away.

## How to prove the product is useful

Use a threat model covering a malicious standard-user process, hostile web content, malformed telemetry, compromised renderer, stale/forged policy, tampered update and interrupted recovery. Privileged administrator and kernel compromise remain explicit limits for the user-mode product. Tamper resistance against an attacker with higher privilege is not established by detecting a service stop.

Maintain separate datasets for detector development, benign compatibility, held-out attack variants and resilience faults. ATT&CK is a vocabulary for behavior, not a percentage checklist; [MITRE's guidance](https://attack.mitre.org/resources/) explicitly advises against chasing complete coverage.

For each live trial record the source revision, package SHA-256, OS/sensor versions, policy, setup checks, actual executed workload, sensor health, raw permitted evidence, expected/observed result, response effect, rollback and exclusions. Reuse `redteam/evaluation/evidence.py` rather than creating a competing scorecard. Live attack and host-modifying validation belongs in disposable, snapshot-capable VMs.

Run the same controlled workloads through endpoint-only, privacy-only and combined modes. Compare missed harmful consequences, incorrect attribution, false incidents, unintended changes and end-to-end latency. Include benign installers/updaters, developer tools, browsers, communication apps, VPN changes and authorized sensitive forms. If combined reasoning adds no measurable benefit, simplify it rather than tuning a showcase until it looks good.

An EDR alert must name its evidence. A mitigation claim needs a receiver- or host-side verified effect. An incident count cannot establish either. Keep a capability manifest linking each promised feature to supported environments, limitations, latest test artifact and expiry/requalification requirements.

## First implementation backlog

1. **SEC-01: replace token bootstrap with authenticated local authority.** Touch `web/server.py`, Electron engine/preload IPC, service installation and focused auth tests. Gate on cross-user and integrity-level tests in a disposable Windows environment.
2. **SEC-02: normalize response outcomes and repair lease accounting.** Touch `edr/response.py`, shared schema/leases and responder contract tests. Mock only the OS boundary; exercise actual adapters, manager and expiry together.
3. **REL-01: require Windows checks before publication.** Touch test runner and `.github/workflows/tests.yml` / `build-windows-exe.yml`. Include Electron, native host, installer and rule changes in relevant triggers; prove failed checks block the matching release.
4. **REL-02: create a package lifecycle qualification harness.** Extend existing redteam/evaluation infrastructure with reversible VM snapshots, state-diff assertions, crash points and artifact hashes. Do not execute it against the developer workstation.
5. **ARCH-01: record the three-component contract and migration.** Add an ADR, capability manifest and versioned service facade tests. Preserve old Aegis exposure routes and all current shadow restrictions.
6. **NYX-01: correct partial-rewrite reporting and add receiver assertions.** Extend the documented leak regression, per-field results and coverage counters before expanding the technique list.
7. **OBS-01: account for subscriber failures, backlog and attribution gaps.** Extend existing health APIs so Aegis cannot display a clean endpoint merely because evidence stopped arriving.

Sequence SEC-01 and SEC-02 first; REL-01 and ARCH-01 can run alongside them. REL-02 depends on a declared test-safety model. Broader enforcement depends on all P0 gates, not completion of a calendar week.

## Defer until the local product earns it

Do not expand fleet management, multi-tenancy, cloud/identity connectors, Linux/macOS, marketplace plugins, autonomous destructive playbooks or a custom malware model during this milestone. Preserve experimental modules without allowing them to enlarge release claims.

The driver track requires a reproducible WDK build, threat review of IOCTLs and policy input, a current Microsoft signing path, Secure Boot/HVCI compatibility, Driver Verifier/stress testing, telemetry-only staging and a recovery/uninstall story before prevention. [Microsoft's signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs) are a release dependency, not something compiling source satisfies.

Reassess scope at each gate. The first meaningful success is a machine whose owner can trust the protection state, understand an incident and recover from a mistaken response. Broad vendor parity requires much more evidence, operating experience and support capacity than this roadmap promises.
