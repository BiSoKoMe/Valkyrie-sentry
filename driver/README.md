# Valkyrie kernel driver (`valkyrie_km`)

Real WDM kernel driver source for Valkyrie's kernel-grade telemetry and
credential-theft protection. **Read the status section before assuming
anything about it.**

---

## Status — what is and is not true

| Claim | Status |
|---|---|
| Real, idiomatic WDK source implementing real kernel primitives | ✅ yes |
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
| Module load visibility (path, remote-backed flag) | `PsSetLoadImageNotifyRoutine` | Unsigned/remote-module hunting (Authenticode verdict left to user mode) |
| **LSASS credential-theft protection** | `ObRegisterCallbacks` pre-op on `PsProcessType` | Strips `PROCESS_VM_READ` & friends from non-trusted handles to `lsass.exe` — blocks Mimikatz-style dumping without denying the open outright |
| Event transport | Control device `\\.\ValkyrieKm` + fixed-size ring + buffered IOCTL pull | Simple, race-free; no pending-IRP cancellation logic to get wrong |

Design rationale, scoring impact, and honest boundaries are in
[`docs/adr/0026-kernel-driver.md`](../docs/adr/0026-kernel-driver.md).

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

1. **Static**: Code Analysis / `/analyze`, the Static Driver Verifier (SDV),
   and the Driver Verifier (`verifier /standard`) with the driver loaded.
2. **Telemetry**: start the service, run benign process/module activity, confirm
   `KernelSensor` events reach the EDR pipeline (Threats page shows lineage).
3. **Protection**: in an **isolated VM**, run a credential-dumping tool (e.g.
   an Atomic Red Team T1003.001 test) and confirm (a) the dump fails / returns
   no secrets and (b) a high `attack_chain`/credential-access incident is
   raised. This is the only test that proves the protection works — and it
   MUST be done in a throwaway VM.
4. **Stability**: 24h+ soak under Driver Verifier; confirm no leaked pool
   (`!poolused` on the `Valk` tag) and clean unload.

Until step 3 passes in a VM, treat the LSASS protection as **unproven**.
