# ADR 0043 - Kernel driver: pre-build static review and hardening

Date: 2026-08-04 . Status: accepted

## Context

`driver/valkyrie_km` has never been compiled. Before spending VM time on
bring-up, the 795 lines of driver source and the Python wire contract were
reviewed statically as hostile code. Kernel defects are not ordinary bugs -
they are bugchecks, or privilege escalation, and both are far cheaper to find
in review than in a debugger.

Six defects were found. Two would have blocked the driver from loading at all;
one is a genuine vulnerability; two are functional defects that only appear
under load.

> **Addendum (same day):** the driver has since been compiled and analysed for
> the first time. That found **four more defects**, three of which meant it did
> not build at all - including one the review had explicitly, and wrongly,
> confirmed as correct. See "Addendum - first real compile" below. The review
> findings stand; the lesson is that they were never sufficient.

## Findings and fixes

### 1. CRITICAL - `/INTEGRITYCHECK` missing: the driver could never load

Both `PsSetCreateProcessNotifyRoutineEx` and `ObRegisterCallbacks` require the
loaded image to be marked for forced integrity checking. Without the linker
flag the kernel refuses registration with `STATUS_ACCESS_DENIED` - and because
`DriverEntry` treats process-notify failure as fatal (`goto fail`), **the
driver would not load at all**. The failure presents as a generic `sc start`
error with no diagnostic. This is the single most time-expensive way for a
first driver bring-up to fail.

**Fix:** `/INTEGRITYCHECK` added to the vcxproj link options, with a
`dumpbin /headers` verification step in the runbook.

### 2. CRITICAL - the control device had no ACL (privilege escalation)

`IoCreateDevice` leaves the default security descriptor, which permits an
**unprivileged** user to open `\\.\ValkyrieKm` and issue IOCTLs. The source
comment asserted "only the trusted Valkyrie service can reach this device";
nothing enforced it. The consequences of that assumption being false:

- push `agent_pid = <malware pid>` -> **the driver protects the malware**, using
  Valkyrie's own self-protection to keep it from being terminated;
- push `block_count = 0` -> prevention silently disabled;
- push `flags = 0` -> tamper protection disabled from user mode.

**Fix:** `IoCreateDeviceSecure` (wdmsec.lib) with
`D:P(A;;GA;;;SY)(A;;GA;;;BA)` - SYSTEM and Administrators only. Plus
defence-in-depth: `SET_POLICY` **pins ownership to the first caller's pid** and
rejects any other, because "an administrator" is a large set on a workstation
and this IOCTL can disable the driver's own tamper resistance. Ownership is
released on that process's exit so a restarted agent can reclaim it - without
that, one agent crash would lock policy updates out permanently. The policy
itself stays in force across the crash, because otherwise killing the agent
would become the bypass self-protection exists to prevent.

### 3. HIGH - `SeLocateProcessImageName` on the hottest path in the kernel

The Ob pre-op callback ran on **every `OpenProcess`/`DuplicateHandle` on the
system** and called `SeLocateProcessImageName` - a paged-pool allocation plus
file-object name resolution - merely to ask "is the target lsass?". On a busy
machine that is thousands of pool allocations per second, and the answer never
changes for a given pid.

**Fix:** a fixed-size, allocation-free pid table (2048 entries, 16 KB,
spinlock-guarded, open addressing with a bounded 32-slot probe). Populated at
process create, cleared at exit (which also handles pid reuse). The expensive
resolution now runs **at most once per pid**, and only for processes that
predate the driver - lsass itself starts long before any third-party driver, so
that fallback is load-bearing and could not simply be deleted.

### 4. HIGH - a false injection alert on every process start

`VlkThreadNotify` reported any thread whose creator process differs from the
target as remote-thread injection. **The first thread of every new process
satisfies that** - the parent creates it - so the driver emitted a false T1055
for every single process launch on the machine. The source comment deferred
this to "user mode correlates it away," which pushes a guaranteed-noise stream
across the ring buffer and into the detection pipeline.

**Fix:** the pid table records whether a process's first thread has been seen;
that one allowance is consumed silently. Unknown pids fail **open** (still
reported) - a noisy true positive beats a silent miss.

### 5. MEDIUM - BYOVD signal was being discarded

`VlkImageNotify` had `UNREFERENCED_PARAMETER(ImageInfo)`, throwing away
`SystemModeImage` - the flag distinguishing a **kernel driver load** from a
user-mode DLL. Loading a signed-but-vulnerable driver is the standard EDR
bypass of the last several years, and it is invisible to every user-mode
sensor. Ring 0 is the only place it can be seen, and the driver was ignoring it.

**Fix:** new `VLK_FLAG_KERNEL_MODULE`, mirrored in `kernel_bridge.py`, which now
raises `kernel_driver_load`. User mode owns matching against a
known-vulnerable-driver list; the driver reports the fact.

### 6. LOW - unsynchronised read of ring state

`GET_STATS` read `g_Count` without `g_RingLock`, racing every callback and able
to report a value that never existed.

**Fix:** read under the lock.

---

## Addendum - first real compile (2026-08-04, later the same day)

The review above ended with "the driver still has not been compiled." It has now
been compiled, analysed with PREfast, and linked to a real `.sys`, with
WDK 10.0.26100 and MSVC 14.44. **It was never loaded** - it is unsigned, and
loading it is out of scope for this work.

The compile alone found **four more defects, three of which meant the driver
could not build at all.** That is the honest headline: a careful manual review
found six real bugs and still shipped source that did not compile. Review and a
compiler find disjoint sets of defects.

### 7. CRITICAL - `SeLocateProcessImageName` was never declared

The driver includes `ntddk.h`. `SeLocateProcessImageName` is declared **only in
`ntifs.h`**. All four call sites produced C4013 ("undefined; assuming extern
returning int"), which `/WX` makes fatal.

**Fix:** include `ntifs.h` (a strict superset of `ntddk.h`).

### 8. CRITICAL - the handle-strip masks were built from undefined identifiers

`PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`,
`PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_SUSPEND_RESUME` live in
`um\winnt.h` - **user mode**. Kernel headers define only `PROCESS_DUP_HANDLE`
(`km\wdm.h`) and `PROCESS_ALL_ACCESS`. Ten hard C2065 errors: both
`VLK_LSASS_STRIP` and the self-protection tamper mask - the two masks that *are*
the driver's protection - were composed of symbols that do not exist.

That `PROCESS_DUP_HANDLE` happens to be available in kernel mode is what made
this survive review: the mask *looks* consistent, and one of its members really
does resolve.

**Fix:** define the six missing rights under `#ifndef`, with the architectural
ACCESS_MASK values.

### 9. CRITICAL - `ObRegisterCallbacks` object type off by one indirection

```c
op.ObjectType = *PsProcessType;   /* wrong */
op.ObjectType =  PsProcessType;   /* correct */
```

`OB_OPERATION_REGISTRATION::ObjectType` is `POBJECT_TYPE *` (`km\wdm.h`:43505) -
a pointer *to* the exported pointer variable. `PsProcessType` already is that
pointer, so it is passed undereferenced.

This is the defect the review was most confident about and most wrong about: a
comment on the line asserted the dereference was required. The nearby pre-op
comparison `Info->ObjectType != *PsProcessType` **is** correct, because
`OB_PRE_OPERATION_INFORMATION::ObjectType` is a plain `POBJECT_TYPE`. The two
structures genuinely differ by one level of indirection, so the wrong form could
be "verified" by looking at the right one.

Consequence had it shipped: `ObRegisterCallbacks` dereferences the field, so it
would have read the first 8 bytes of the `OBJECT_TYPE` structure and used that as
the object type - a rejected registration (silent total loss of LSASS
protection) or a bugcheck inside `DriverEntry`.

### 10. MEDIUM - SAL annotations that disabled the analysers

PREfast found three annotation defects. None is a live memory bug; all three
**stop the static analysers from being able to find one**, which is worse than
having no annotation:

- `VlkCopyPath(_Out_ USHORT *dst, ...)` - C6386. Bare `_Out_` on a pointer claims
  exactly one element; the function writes 520 bytes. Every current caller
  passes a real `USHORT[VLK_PATH_LEN]`, so there is no overrun today - but a
  genuinely undersized buffer passed here later would surface as this same
  already-dismissed warning. Now `_Out_writes_(VLK_PATH_LEN)`.
- `VlkRingPop(_Out_writes_(max) ...)` - C6101. Promises all `max` elements are
  filled; the empty-ring path writes none. Now `_Out_writes_to_(max, return)`.
  The copy-out was already correct (`Information = popped * sizeof(VLK_EVENT)`),
  so no uninitialised pool leaked - but the annotation is exactly what would
  have prevented the analyser from saying so if it had.
- Five x C28023: `VlkUnload`, `VlkCreateClose` (x2), `VlkDeviceControl` and
  `VlkRegistryCallback` lacked `_Function_class_`. **This is how Static Driver
  Verifier discovers entry points.** Without them SDV has no dispatch routines
  to explore, so its rules pass by examining nothing - and report clean.

**Result:** PREfast reports **0 warnings** citing `valkyrie_km.c`. The only
remaining warnings are two broken SAL annotations in Microsoft's own `ntddk.h`
(`WheaErrorRecordBuilderAddPacket`, C28230/C28285), which we cannot fix.

### Build tooling

`driver/build_km.bat` added. `msbuild valkyrie_km.vcxproj` **cannot work on a
machine without the WDK's Visual Studio extension**: `PlatformToolset=
WindowsKernelModeDriver10.0` is registered by `WDK.vsix`, not by the WDK. A box
can have complete WDK headers, libs and `build\*.targets` and still fail, with an
error that reads like a corrupt project file. The script drives `cl`/`link`
directly with equivalent flags.

Two traps it encodes, both of which cost real time here:

- `Include\<sdk>\km\crt` must precede the MSVC include dir, or `crtdefs.h` pulls
  in `corecrt.h`, which does not exist in a kernel build (fatal C1083).
- Do not `#define _KERNEL_MODE`; `/kernel` defines it, and redefining a reserved
  macro is C4117 -> fatal under `/WX`.

The script's PREfast gate was verified by reintroducing defect #9 and confirming
a non-zero exit, then reverting - a gate that has never been seen to fail is not
known to work.

### Static Driver Verifier - NOT RUN

SDV is **not installed on this machine** and could not be run. `Tools\dvl\dvl.exe`
(the report generator) is present, and `build\10.0.26100.0\WindowsDriver.Sdv.targets`
(the MSBuild glue) is present, but the SDV engine itself - `staticdv.exe` and its
rule set - is absent, as is any `sdv\` directory. SDV is additionally only
drivable through msbuild, which needs the same missing vsix.

So: **the driver has not been verified by SDV, and no claim is made about the
properties SDV checks** (IRQL discipline, correct DDI usage, lock/IRQL pairing,
`IoCompleteRequest` paths). The `_Function_class_` annotations added under defect
#10 are the prerequisite for SDV to be meaningful when it is eventually run;
without them a future SDV pass would have reported clean while exploring nothing.

## Consequences

- Wire contract re-verified byte-for-byte after the changes: `VLK_EVENT` = 1072
  bytes, `VLK_POLICY` = 1040 bytes, identical in C and Python.
  `tests/test_kernel_bridge.py` passes.
- Brace/paren/bracket balance verified; all new symbols defined and referenced.
- The driver **compiles clean at `/W4 /WX`**, passes PREfast with the driver
  plugin with zero warnings on our source, and links to a 26 KB native x64 `.sys`
  marked "Check integrity" (`dumpbin /headers`), importing `ObRegisterCallbacks`,
  `CmRegisterCallbackEx`, `PsSetCreateProcessNotifyRoutineEx`,
  `IoCreateDeviceSecure` and `SeLocateProcessImageName`.
- **It has still never been loaded or run.** Compiling proves it is well-formed;
  it proves nothing about runtime behaviour. Everything in `BRINGUP.md` remains
  to be done, in a disposable VM.
- `driver/BRINGUP.md` written: staged bring-up (telemetry -> Verifier -> LSASS
  protection -> prevention) with an explicit gate list per stage and a recovery
  table.

## Honest boundaries - unchanged by this work

- No minifilter: no file visibility, no pre-write ransomware blocking, no
  quarantine, no on-disk self-protection.
- No WFP callout: no kernel network visibility or enforcement.
- No ETW-TI: memory operations (`VirtualAllocEx`, `WriteProcessMemory`) remain
  invisible. Requires PPL, which requires an ELAM certificate Microsoft grants
  only to vetted AV vendors.
- **Prevention matches the FNV-1a hash of the lowercased basename.** Renaming
  the file bypasses it completely. Adequate for a self-test, inadequate against
  real malware; SHA256 image hashing is the real answer and is not built. This
  must not be described as malware prevention.
- Ob handle-stripping raises the cost of tampering; it does not defeat a
  determined admin-level attacker without PPL.
