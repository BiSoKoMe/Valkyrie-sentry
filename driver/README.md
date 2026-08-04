# Valkyrie kernel driver (`valkyrie_km`)

Real WDM kernel driver source for Valkyrie's kernel-grade telemetry, credential-
theft protection, **process-launch prevention**, and **agent self-protection**.
**Read the status section before assuming anything about it.**

---

## Status — what is and is not true

| Claim | Status |
|---|---|
| Real, idiomatic WDK source implementing real kernel primitives | ✅ yes |
| **Statically reviewed as hostile code** | ✅ 2026-08-04 — 6 defects found + fixed, see [ADR 0043](../docs/adr/0043-driver-hardening.md) |
| **Staged bring-up runbook** | ✅ [`BRINGUP.md`](BRINGUP.md) |
| Compiles in this repo / CI | ❌ no — no WDK in the build env |
| Signed | ❌ no — needs an EV cert + Microsoft attestation (or test-signing) |
| Loaded / running anywhere | ❌ no |
| Detonation-tested against real tooling (Mimikatz, etc.) | ❌ no |
| The Python product works without it | ✅ yes — the bridge self-disables |

This directory is a **buildable, reviewable driver component and its
integration**, not a shipped, validated binary. Nothing in Valkyrie claims
"kernel protection active" unless this driver is actually built, signed,
loaded, and the user-mode bridge reports the device open. Until then the
product runs exactly as it does today (userland sensors only).

Treat any load of an unsigned/self-built kernel driver as **development only,
on a machine you can afford to crash** — a kernel bug is a bugcheck (BSOD).

---

## What it does

| Capability | Kernel primitive | Value |
|---|---|---|
| Process create/exit + **authoritative lineage** (pid, ppid, image) | `PsSetCreateProcessNotifyRoutineEx` | Ground-truth parent PIDs for the kill-chain correlator — no racy user-mode enumeration |
| **Process-launch PREVENTION** (deny on create) | same callback → `CreationStatus = STATUS_ACCESS_DENIED` | The detect→**prevent** leap: an image on the pushed block list never starts. Triple-guarded (see below) |
| Module load visibility (path, remote-backed flag) | `PsSetLoadImageNotifyRoutine` | Unsigned/remote-module hunting (Authenticode verdict left to user mode) |
| **Remote-thread injection** detection | `PsSetCreateThreadNotifyRoutine` | Cross-process thread creation = `CreateRemoteThread` injection (T1055) |
| **Autostart-registry** detection (Run/RunOnce/Services) | `CmRegisterCallbackEx` (detection-only) | Kernel-authoritative persistence visibility (T1547/T1543); never blocks the registry op |
| **LSASS credential-theft protection** | `ObRegisterCallbacks` pre-op on `PsProcessType` | Strips `PROCESS_VM_READ` & friends from non-trusted handles to `lsass.exe` — blocks Mimikatz-style dumping without denying the open outright |
| **Agent self-protection** (tamper resistance) | same Ob pre-op, by agent pid | Strips `PROCESS_TERMINATE`/inject rights from handles to the Valkyrie agent — malware/admin can't kill the protection |
| Enforcement policy intake | `VLK_IOCTL_SET_POLICY` (fixed-size, validated) | User mode pushes the block list + agent pid + enable bits; kernel never parses a variable list |
| Event transport | Control device `\\.\ValkyrieKm` + fixed-size ring + buffered IOCTL pull | Simple, race-free; no pending-IRP cancellation logic to get wrong |

### Safety design (the CrowdStrike-2024 lesson: a kernel driver's first duty is to not brick the machine)

- **Prevention and self-protection default OFF.** The driver is pure telemetry
  until the trusted user-mode service pushes a policy that enables them. A
  driver that ships blocking-on is how you take down a fleet.
- **The create-block never denies an image under `\Windows\`** (System32 etc.),
  so a wrong — or hostile — block list can never stop the OS from booting or
  running critical processes.
- **The policy block list is a fixed, bounded array** (`VLK_MAX_BLOCK_HASHES`).
  `SET_POLICY` validates size + version and clamps the count; the kernel never
  trusts a length that could walk off the array.
- **Registry callback is detection-only** and always returns `STATUS_SUCCESS` —
  it never alters a registry op, because a registry callback that gets blocking
  wrong hangs the whole machine.
- **Everything fails OPEN**: on any doubt, allocation failure, or unresolved
  name, the driver allows the operation and drops the event.

Design rationale, scoring impact, and honest boundaries are in
[`docs/adr/0026-kernel-driver.md`](../docs/adr/0026-kernel-driver.md) and
[`docs/adr/0031-kernel-prevention-selfprotect.md`](../docs/adr/0031-kernel-prevention-selfprotect.md).

The wire format is the single shared contract in
[`valkyrie_km/valkyrie_shared.h`](valkyrie_km/valkyrie_shared.h); the user-mode
side mirrors it in [`valkyrie/kernel_bridge.py`](../valkyrie/kernel_bridge.py)
and is unit-tested (`tests/test_kernel_bridge.py`).

---

## Build

Requires **Visual Studio 2022** + the **Windows Driver Kit (WDK)** matching your
SDK, or the **EWDK** (self-contained). Then:

```powershell
# From a Developer / EWDK command prompt, in driver\valkyrie_km:
msbuild valkyrie_km.vcxproj /p:Configuration=Release /p:Platform=x64
# → x64\Release\valkyrie_km.sys
```

## Sign

The driver must be signed to load on a normal Windows 10/11 system:

- **Production**: an **EV code-signing certificate** submitted to the Microsoft
  Hardware Dev Center for **attestation signing**. The LSASS `ObRegisterCallbacks`
  path additionally requires the binary to carry the anti-malware/`ELAM`-class
  entitlement, which Microsoft grants only to vetted AV vendors — without it,
  `ObRegisterCallbacks` returns `STATUS_ACCESS_DENIED` and the driver still runs
  as telemetry-only (it degrades, it does not crash).
- **Development**: enable test-signing and use a self-signed test cert:
  ```powershell
  bcdedit /set testsigning on   # reboot required; shows a desktop watermark
  # signtool sign /v /s PrivateCertStore /n ValkyrieTest /fd sha256 valkyrie_km.sys
  ```

## Load / unload (development)

```powershell
sc create ValkyrieKm type= kernel binPath= C:\path\valkyrie_km.sys
sc start  ValkyrieKm      # driver creates \\.\ValkyrieKm
# ... the Python service's KernelSensor now reports available() == True ...
sc stop   ValkyrieKm
sc delete ValkyrieKm
```

## Validate (the honest checklist before trusting it)

All of this MUST be done in a **throwaway VM** — a kernel bug is a bugcheck.

1. **Static**: Code Analysis / `/analyze`, the Static Driver Verifier (SDV),
   and the Driver Verifier (`verifier /standard`) with the driver loaded.
2. **Telemetry**: start the service, run benign process/module/thread activity,
   confirm `KernelSensor` events reach the EDR pipeline (Threats page shows
   lineage), and that a benign machine produces **no** thread-injection or
   registry false positives at volume.
3. **LSASS protection**: run a credential-dumping tool (e.g. an Atomic Red Team
   T1003.001 test) and confirm (a) the dump fails / returns no secrets and (b) a
   high credential-access incident is raised.
4. **Prevention**: push a policy with `prevention=True` and a test binary's
   basename on the block list; confirm (a) launching it is denied
   (`STATUS_ACCESS_DENIED`), (b) a `kernel.prevent` **blocked** incident is
   raised, and — critically — (c) that a block list containing a System32 name
   does **not** stop that system binary (the `\Windows\` safety rail holds).
5. **Self-protection**: push a policy with `self_protect=True` and the agent pid;
   from another non-SYSTEM process, attempt `OpenProcess(PROCESS_TERMINATE)` +
   `TerminateProcess` on the agent and confirm it fails and raises a `tamper`
   incident.
6. **Stability**: 24h+ soak under Driver Verifier with all callbacks active
   (including the high-frequency registry callback); confirm no leaked pool
   (`!poolused` on the `Valk` tag), no measurable registry-path latency
   regression, and clean unload.

Until steps 3–5 pass in a VM, treat every protection here as **unproven**.
Prevention and self-protection stay OFF by default precisely so that an unbuilt/
unvalidated driver can never brick a machine before this checklist is done.
