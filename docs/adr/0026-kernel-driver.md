# ADR 0026 - Kernel driver: telemetry + LSASS protection (source component)

Date: 2026-07-24 . Status: accepted (source component; not built/shipped) . Follows: ADR 0025

## Context

Every prior ADR that hit a wall named the same one: capabilities that need
kernel visibility - tamper-proof process lineage, in-kernel handle
interception, pre-execution/pre-write blocking - were **documented as out of
scope for a user-mode agent** rather than faked (ADRs 0001, 0023, 0025). That
honesty is correct and stays. But "out of scope forever, undocumented" is
weaker than "here is the real extension point, built to the edge of what this
environment can validate." The request was explicit: build the kernel driver.

The hard constraint is equally explicit: this repo's build environment has **no
WDK, no code-signing certificate, and no kernel-debug/detonation rig**. A
driver written here cannot be compiled, signed, loaded, or tested here.
Shipping a stub and calling it "kernel protection" would be exactly the
fake-functionality every other ADR refused. So the decision is about *what
form* an honest kernel contribution takes.

## Decision

Add `driver/valkyrie_km/` - a **real, reviewable, buildable WDM driver source
component** plus its **fully-integrated, tested user-mode bridge** - with a
status contract that never overstates it.

Kernel side (`valkyrie_km.c`, `valkyrie_shared.h`), scoped to the highest-value,
lowest-risk primitives:
- `PsSetCreateProcessNotifyRoutineEx` - authoritative `(pid, ppid, image)`.
  This directly feeds the ADR 0025 lineage correlator with ground truth
  instead of racy user-mode process enumeration.
- `PsSetLoadImageNotifyRoutine` - module-load facts; signature verdicts are
  deliberately left to user-mode Authenticode (the driver does not claim
  in-kernel signature checking it doesn't implement).
- `ObRegisterCallbacks` pre-op on `PsProcessType` - **strips** memory-access
  rights (`PROCESS_VM_READ`/`VM_WRITE`/`VM_OPERATION`/`DUP_HANDLE`/
  `CREATE_THREAD`) from non-trusted handles to `lsass.exe`. It never denies the
  open outright and never touches SYSTEM/kernel callers - the conservative,
  OS-safe pattern (same defence class as RunAsPPL) that blocks Mimikatz-style
  dumping without risking a deadlock.
- A control device with a **fixed-size, spinlock-guarded ring buffer** pulled
  by a **buffered IOCTL** (a poll, not a pending-IRP inverted call - chosen
  because polling has no IRP-cancellation race to get subtly wrong and BSOD
  on; the small efficiency cost is the right trade for a first driver).

Fail-safe everywhere: on any uncertainty the driver **allows** the operation
and drops the event rather than blocking or touching unsafe memory.

User-mode side (`valkyrie/kernel_bridge.py`): a `Sensor` (hosted by the existing
resilient `SensorManager`) whose `available()` is False unless the device
actually opens, so the product is **unchanged** when the driver is absent - the
default state. Kernel records normalise into the SAME `TelemetryEvent` stream
as every other sensor, so they flow through EventBus -> correlation -> kill-chain
with zero new plumbing. An LSASS-block record becomes a real high-severity
`T1003.001` credential-access detection that can anchor a multi-stage chain.

## Consequences

- Valkyrie now has a genuine kernel extension point, not a hand-wave: real
  primitives, a real wire contract, real integration, and a build/sign/load/
  validate procedure (`driver/README.md`).
- The **user-mode half is testable now and tested**: `tests/test_kernel_bridge.py`
  (24 checks) exercises record parsing for every event kind, version/short-buffer
  rejection, FILETIME conversion, lineage plumbing (ppid), graceful absence, and
  the end-to-end LSASS-block -> credential-access detection through the unchanged
  ingest path. The efficacy gate is unaffected (100% / 0%).

## Honest boundaries (what this is NOT)

- **Not built, not signed, not loaded, not detonation-tested** in this repo.
  The `.c`/`.h`/`.inf`/`.vcxproj` are real and buildable with a WDK, but this
  environment cannot compile or validate them. The status table in
  `driver/README.md` is the source of truth; nothing claims otherwise.
- **LSASS protection is unproven until VM detonation.** Correct-looking Ob
  callback code is not the same as a confirmed-blocked Mimikatz run. The README
  makes VM detonation (Atomic Red Team T1003.001) the gate before trusting it.
- **Loading requires signing**, and the Ob-callback path needs the
  anti-malware/ELAM-class entitlement Microsoft grants only to vetted vendors;
  without it the driver degrades to telemetry-only. This is a real distribution
  constraint, not a code problem.
- **Scope is deliberately narrow.** No minifilter (pre-write ransomware
  blocking), no WFP network callout, no registry callbacks - those are higher-
  risk and belong in later, separately-validated ADRs. This driver does the
  three things it does, correctly and conservatively, and says so.
