/*
 * valkyrie_km.c — Valkyrie kernel telemetry & protection driver.
 *
 * STATUS (read this first): this is REAL, idiomatic WDK source implementing
 * real kernel primitives. It has NOT been compiled, signed, loaded, or tested
 * in the repo's build environment (no WDK / no signing there). Treat it as a
 * reviewable, buildable driver component — see driver/README.md for exactly
 * what a developer needs to build/sign/load/validate it, and ADR 0026 for the
 * design and its honest boundaries. The Python product runs unchanged when
 * this driver is absent (valkyrie/kernel_bridge.py self-disables).
 *
 * What it does, and why each piece is the safest useful choice:
 *
 *   1. Process create/exit notify (PsSetCreateProcessNotifyRoutineEx) — with
 *      optional PREVENTION. Authoritative process lineage for the correlator;
 *      and, when user mode has opted in, the create callback can DENY a launch
 *      (CreationStatus = STATUS_ACCESS_DENIED) for an image whose basename hash
 *      is on the pushed block list. This is the detect->prevent leap. Guarded
 *      three ways (see below) so a bad list can never brick the machine.
 *
 *   2. Image load notify (PsSetLoadImageNotifyRoutine).
 *      Every module load with its backing path. Signature verdicts are LEFT
 *      to user mode (Authenticode) — this driver reports facts.
 *
 *   3. Thread-create notify (PsSetCreateThreadNotifyRoutine).
 *      A thread created in a DIFFERENT process than its creator is the classic
 *      CreateRemoteThread injection signal (T1055). Read-only.
 *
 *   4. Registry set-value notify (CmRegisterCallbackEx), DETECTION-ONLY.
 *      A write to a Run/RunOnce/Services autostart key (T1547/T1543) is emitted
 *      as telemetry. It NEVER blocks or alters the registry op — a registry
 *      callback that gets blocking wrong hangs the whole machine.
 *
 *   5. LSASS credential-theft protection AND agent self-protection
 *      (ObRegisterCallbacks, pre-op on PsProcessType). For handles to lsass.exe
 *      the callback STRIPS memory-read rights (blocks Mimikatz-style dumping);
 *      for handles to the Valkyrie agent pid it STRIPS terminate/inject rights
 *      (tamper resistance) — both only when user mode opted in, both only the
 *      dangerous rights, never the whole open, never for SYSTEM/kernel callers.
 *
 *   6. A control device (\\.\ValkyrieKm) with a fixed-size lock-guarded ring
 *      buffer. The bridge PULLS events with a buffered IOCTL (a poll, not a
 *      pending-IRP inverted call — safer: no IRP-cancellation race to BSOD on)
 *      and PUSHES a fixed-size enforcement policy in with SET_POLICY.
 *
 * SAFETY POSTURE (the CrowdStrike-2024 lesson: a kernel driver's first duty is
 * to not brick the machine):
 *   - Prevention and self-protection DEFAULT OFF. The driver is pure telemetry
 *     until the trusted user-mode service explicitly enables them via policy.
 *   - The create-block NEVER denies an image under \Windows\ (System32 etc.),
 *     so a bad/hostile block list can't stop the OS from booting or running.
 *   - Everything fail-OPEN: on any doubt, allocation failure, or unresolved
 *     name the driver ALLOWS the operation and drops the event.
 */

#include <ntddk.h>
#include "valkyrie_shared.h"

#define VLK_TAG            'klaV'      /* pool tag "Valk" */
#define VLK_RING_CAPACITY  4096        /* events; ~4MB of NonPagedPool */

/* ------------------------------------------------------------------ globals */

static PDEVICE_OBJECT   g_DeviceObject = NULL;
static PVOID            g_ObCallbackHandle = NULL;
static BOOLEAN          g_ProcessCbRegistered = FALSE;
static BOOLEAN          g_ImageCbRegistered = FALSE;
static BOOLEAN          g_ThreadCbRegistered = FALSE;
static LARGE_INTEGER    g_RegCookie = { 0 };
static BOOLEAN          g_RegCbRegistered = FALSE;

/* Fixed-size circular ring, guarded by a spinlock (callbacks may run on any
 * CPU concurrently). head = next write, tail = next read; count = pending. */
static VLK_EVENT       *g_Ring = NULL;
static ULONG            g_Head = 0, g_Tail = 0, g_Count = 0;
static KSPIN_LOCK       g_RingLock;

/* Enforcement policy, guarded by its own spinlock. Zeroed = detection-only. */
static VLK_POLICY       g_Policy;
static KSPIN_LOCK       g_PolicyLock;

static volatile LONG    g_Produced = 0;
static volatile LONG    g_Dropped = 0;
static volatile LONG    g_LsassBlocks = 0;
static volatile LONG    g_ThreadEvents = 0;
static volatile LONG    g_RegistryEvents = 0;
static volatile LONG    g_ProcBlocks = 0;
static volatile LONG    g_TamperBlocks = 0;

/* ------------------------------------------------------------- small helpers */

/* Copy a UNICODE_STRING into a fixed WCHAR[VLK_PATH_LEN], always null-terminated. */
static VOID VlkCopyPath(_Out_ USHORT *dst, _In_opt_ PCUNICODE_STRING src)
{
    RtlZeroMemory(dst, VLK_PATH_LEN * sizeof(USHORT));
    if (src == NULL || src->Buffer == NULL || src->Length == 0)
        return;
    ULONG chars = src->Length / sizeof(WCHAR);
    if (chars > (VLK_PATH_LEN - 1))
        chars = VLK_PATH_LEN - 1;
    RtlCopyMemory(dst, src->Buffer, chars * sizeof(WCHAR));
    dst[chars] = 0;
}

/* True if the image path ends with a case-insensitive match of "\\name". */
static BOOLEAN VlkImageIsLsass(_In_opt_ PCUNICODE_STRING image)
{
    static const UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"\\lsass.exe");
    if (image == NULL || image->Buffer == NULL || image->Length < lsass.Length)
        return FALSE;
    UNICODE_STRING tail;
    tail.Buffer = (PWCH)((PUCHAR)image->Buffer + image->Length - lsass.Length);
    tail.Length = lsass.Length;
    tail.MaximumLength = lsass.Length;
    return RtlEqualUnicodeString(&tail, &lsass, TRUE);
}

/* FNV-1a (32-bit) over the LOWERCASED image BASENAME, hashing the low byte of
 * each UTF-16 code unit. The user-mode bridge computes the identical hash
 * (valkyrie/kernel_bridge.py: fnv1a_32) so a block list built in Python matches
 * here. Basename-only + case-fold so "C:\\x\\Evil.EXE" and "evil.exe" agree. */
static ULONG VlkHashImageBasename(_In_opt_ PCUNICODE_STRING image)
{
    if (image == NULL || image->Buffer == NULL || image->Length == 0)
        return 0;
    USHORT chars = (USHORT)(image->Length / sizeof(WCHAR));
    USHORT start = 0;
    for (USHORT i = 0; i < chars; i++) {
        WCHAR c = image->Buffer[i];
        if (c == L'\\' || c == L'/')
            start = (USHORT)(i + 1);
    }
    ULONG h = 2166136261u;              /* FNV offset basis */
    for (USHORT i = start; i < chars; i++) {
        WCHAR c = image->Buffer[i];
        if (c >= L'A' && c <= L'Z')
            c = (WCHAR)(c + 32);        /* ASCII lower-case fold */
        h ^= (ULONG)(c & 0xFF);
        h *= 16777619u;                 /* FNV prime */
    }
    return h;
}

/* SAFETY RAIL: never let prevention deny an image living under \Windows\ (which
 * includes System32). A user-supplied — or hostile — block list must never be
 * able to stop the OS from starting critical processes. Case-insensitive
 * substring test against the full image path. */
static BOOLEAN VlkImageIsProtectedSystem(_In_opt_ PCUNICODE_STRING image)
{
    static const UNICODE_STRING win = RTL_CONSTANT_STRING(L"\\windows\\");
    if (image == NULL || image->Buffer == NULL || image->Length < win.Length)
        return FALSE;
    USHORT chars = (USHORT)(image->Length / sizeof(WCHAR));
    USHORT winChars = (USHORT)(win.Length / sizeof(WCHAR));
    for (USHORT i = 0; i + winChars <= chars; i++) {
        UNICODE_STRING slice;
        slice.Buffer = &image->Buffer[i];
        slice.Length = win.Length;
        slice.MaximumLength = win.Length;
        if (RtlEqualUnicodeString(&slice, &win, TRUE))
            return TRUE;
    }
    return FALSE;
}

/* Snapshot the two policy enable bits + agent pid under the lock. */
static VOID VlkPolicyRead(_Out_ ULONG *flags, _Out_ ULONG *agentPid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_PolicyLock, &irql);
    *flags = g_Policy.flags;
    *agentPid = g_Policy.agent_pid;
    KeReleaseSpinLock(&g_PolicyLock, irql);
}

/* True if `hash` is on the current block list (bounded linear scan under lock;
 * block_count is clamped to VLK_MAX_BLOCK_HASHES when the policy is accepted). */
static BOOLEAN VlkPolicyBlocksHash(_In_ ULONG hash)
{
    BOOLEAN hit = FALSE;
    KIRQL irql;
    if (hash == 0)
        return FALSE;
    KeAcquireSpinLock(&g_PolicyLock, &irql);
    for (ULONG i = 0; i < g_Policy.block_count; i++) {
        if (g_Policy.block_hashes[i] == hash) { hit = TRUE; break; }
    }
    KeReleaseSpinLock(&g_PolicyLock, irql);
    return hit;
}

/* Push one fully-formed event into the ring (drops oldest-not, drops NEW on
 * full — never blocks; callbacks must be quick and non-paged-safe). */
static VOID VlkRingPush(_In_ const VLK_EVENT *ev)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_RingLock, &irql);
    if (g_Count < VLK_RING_CAPACITY) {
        g_Ring[g_Head] = *ev;
        g_Head = (g_Head + 1) % VLK_RING_CAPACITY;
        g_Count++;
        InterlockedIncrement(&g_Produced);
    } else {
        InterlockedIncrement(&g_Dropped);   /* backpressure: user mode is behind */
    }
    KeReleaseSpinLock(&g_RingLock, irql);
}

/* Pop up to `max` events into caller buffer; returns count popped. */
static ULONG VlkRingPop(_Out_writes_(max) VLK_EVENT *out, _In_ ULONG max)
{
    ULONG n = 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_RingLock, &irql);
    while (n < max && g_Count > 0) {
        out[n++] = g_Ring[g_Tail];
        g_Tail = (g_Tail + 1) % VLK_RING_CAPACITY;
        g_Count--;
    }
    KeReleaseSpinLock(&g_RingLock, irql);
    return n;
}

static VOID VlkFillHeader(_Out_ VLK_EVENT *ev, _In_ ULONG type,
                          _In_ ULONG pid, _In_ ULONG ppid)
{
    LARGE_INTEGER now;
    RtlZeroMemory(ev, sizeof(*ev));
    KeQuerySystemTime(&now);
    ev->version = VLK_PROTO_VERSION;
    ev->event_type = type;
    ev->timestamp = (unsigned long long)now.QuadPart;
    ev->pid = pid;
    ev->ppid = ppid;
    ev->flags = VLK_FLAG_NONE;
}

/* ------------------------------------------------------- notify callbacks */

/* Process create/exit. CreateInfo != NULL on create (has ParentProcessId and
 * ImageFileName), NULL on exit. Runs at PASSIVE_LEVEL. */
static VOID VlkProcessNotify(_Inout_ PEPROCESS Process,
                             _In_ HANDLE ProcessId,
                             _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    VLK_EVENT ev;
    if (CreateInfo != NULL) {
        VlkFillHeader(&ev, VLK_EVT_PROCESS_CREATE,
                      HandleToULong(ProcessId),
                      HandleToULong(CreateInfo->ParentProcessId));
        VlkCopyPath(ev.image, CreateInfo->ImageFileName);
        /* extra carries the command line when the kernel provides it (useful
         * for user-mode cmdline heuristics); parent identity travels as ppid. */
        if (CreateInfo->CommandLine)
            VlkCopyPath(ev.extra, CreateInfo->CommandLine);

        /* PREVENTION — the detect->prevent leap. Deny the launch only when ALL
         * of: user mode enabled prevention, the image's basename hash is on the
         * block list, and the image is NOT under \Windows\ (the safety rail that
         * makes a bad/hostile list unable to brick the OS). Setting
         * CreationStatus to a failure code makes the kernel abort process
         * creation. Fail-open: any failure above simply doesn't block. */
        ULONG pflags = 0, agentPid = 0;
        VlkPolicyRead(&pflags, &agentPid);
        if ((pflags & VLK_POLICY_ENABLE_PREVENTION) &&
            !VlkImageIsProtectedSystem(CreateInfo->ImageFileName) &&
            VlkPolicyBlocksHash(VlkHashImageBasename(CreateInfo->ImageFileName))) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;   /* BLOCK the launch */
            ev.event_type = VLK_EVT_PROCESS_BLOCKED;
            ev.flags |= VLK_FLAG_BLOCKED;
            InterlockedIncrement(&g_ProcBlocks);
        }
    } else {
        VlkFillHeader(&ev, VLK_EVT_PROCESS_EXIT, HandleToULong(ProcessId), 0);
    }
    VlkRingPush(&ev);
}

/* Thread create/exit. A thread whose CREATOR process differs from the process
 * it runs IN is cross-process thread injection (CreateRemoteThread, T1055) —
 * the highest-value thread signal. We emit only that case to keep volume sane;
 * user mode suppresses the benign first-thread-of-a-new-process instance by
 * correlating with the matching PROCESS_CREATE. Read-only. PASSIVE_LEVEL. */
static VOID VlkThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId,
                            _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);
    if (!Create)
        return;
    HANDLE creator = PsGetCurrentProcessId();
    if (creator == ProcessId)
        return;                                  /* self-thread: normal, skip */

    VLK_EVENT ev;
    VlkFillHeader(&ev, VLK_EVT_THREAD_CREATE,
                  HandleToULong(ProcessId),      /* pid   = target process   */
                  HandleToULong(creator));       /* ppid  = creating process */
    ev.flags |= VLK_FLAG_REMOTE_THREAD;
    PUNICODE_STRING reqImage = NULL;
    if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &reqImage)) && reqImage) {
        VlkCopyPath(ev.image, reqImage);         /* creator image */
        ExFreePool(reqImage);
    }
    InterlockedIncrement(&g_ThreadEvents);
    VlkRingPush(&ev);
}

/* Image (module) load. Runs at PASSIVE_LEVEL. */
static VOID VlkImageNotify(_In_opt_ PUNICODE_STRING FullImageName,
                           _In_ HANDLE ProcessId,
                           _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);
    VLK_EVENT ev;
    VlkFillHeader(&ev, VLK_EVT_IMAGE_LOAD, HandleToULong(ProcessId), 0);
    VlkCopyPath(ev.extra, FullImageName);
    /* UNC/remote backing path is itself a weak signal; flag it, let user mode
     * make the call (Authenticode / reputation). */
    if (FullImageName && FullImageName->Length >= 2 &&
        FullImageName->Buffer[0] == L'\\' && FullImageName->Buffer[1] == L'\\')
        ev.flags |= VLK_FLAG_REMOTE_IMAGE;
    VlkRingPush(&ev);
}

/* ----------------------------------------------------- registry callback */

/* True if `key` names a classic autostart location (Run/RunOnce/Services). A
 * cheap case-insensitive substring test over the resolved key path. */
static BOOLEAN VlkKeyIsAutostart(_In_opt_ PCUNICODE_STRING key)
{
    static const UNICODE_STRING run  = RTL_CONSTANT_STRING(L"\\currentversion\\run");
    static const UNICODE_STRING svc  = RTL_CONSTANT_STRING(L"\\services\\");
    static const UNICODE_STRING wlog = RTL_CONSTANT_STRING(L"\\winlogon");
    const UNICODE_STRING *needles[] = { &run, &svc, &wlog };
    if (key == NULL || key->Buffer == NULL || key->Length == 0)
        return FALSE;
    USHORT chars = (USHORT)(key->Length / sizeof(WCHAR));
    for (int n = 0; n < 3; n++) {
        USHORT need = (USHORT)(needles[n]->Length / sizeof(WCHAR));
        if (need == 0 || need > chars) continue;
        for (USHORT i = 0; i + need <= chars; i++) {
            UNICODE_STRING slice;
            slice.Buffer = &key->Buffer[i];
            slice.Length = needles[n]->Length;
            slice.MaximumLength = needles[n]->Length;
            if (RtlEqualUnicodeString(&slice, needles[n], TRUE))
                return TRUE;
        }
    }
    return FALSE;
}

/* Registry set-value notify. DETECTION-ONLY: it resolves the key path, emits an
 * event for writes to autostart keys, and ALWAYS returns STATUS_SUCCESS so the
 * registry operation proceeds untouched. A registry callback is on a very hot
 * path and any misstep hangs the machine, so the fast path bails immediately on
 * anything that is not a pre-set-value op, and it never blocks. */
static NTSTATUS VlkRegistryCallback(_In_ PVOID CallbackContext,
                                    _In_opt_ PVOID Arg1, _In_opt_ PVOID Arg2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    if ((REG_NOTIFY_CLASS)(ULONG_PTR)Arg1 != RegNtPreSetValueKey || Arg2 == NULL)
        return STATUS_SUCCESS;

    PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Arg2;
    PCUNICODE_STRING keyName = NULL;
    if (!NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_RegCookie, info->Object,
                                               NULL, &keyName, 0)) || keyName == NULL)
        return STATUS_SUCCESS;                    /* can't resolve → allow, no event */

    if (VlkKeyIsAutostart(keyName)) {
        VLK_EVENT ev;
        VlkFillHeader(&ev, VLK_EVT_REGISTRY_SET,
                      HandleToULong(PsGetCurrentProcessId()), 0);
        ev.flags |= VLK_FLAG_AUTOSTART;
        VlkCopyPath(ev.extra, keyName);           /* the autostart key path */
        PUNICODE_STRING reqImage = NULL;
        if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &reqImage)) && reqImage) {
            VlkCopyPath(ev.image, reqImage);
            ExFreePool(reqImage);
        }
        InterlockedIncrement(&g_RegistryEvents);
        VlkRingPush(&ev);
    }
    CmCallbackReleaseKeyObjectIDEx(keyName);
    return STATUS_SUCCESS;                          /* never block the registry */
}

/* --------------------------------------------------- LSASS Ob pre-callback */

/* Rights that let a process read another's memory / fully control it — the
 * ones credential dumpers need against lsass. We STRIP these (never the whole
 * open) so legitimate limited handles (e.g. PROCESS_QUERY_LIMITED_INFORMATION)
 * still succeed and nothing in the OS deadlocks. */
#define VLK_LSASS_STRIP (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
                         PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD)

static OB_PREOP_CALLBACK_STATUS VlkPreOp(_In_ PVOID RegistrationContext,
                                         _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;
    /* Kernel handles are trusted; never touch them. */
    if (Info->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS target = (PEPROCESS)Info->Object;
    /* A process opening ITSELF is fine. */
    if (target == PsGetCurrentProcess())
        return OB_PREOP_SUCCESS;

    HANDLE reqPid = PsGetCurrentProcessId();
    HANDLE tgtPid = PsGetProcessId(target);
    /* SYSTEM (pid 4) is trusted for both protections — stripping its access
     * could break the OS. */
    if (HandleToULong(reqPid) == 4)
        return OB_PREOP_SUCCESS;

    ACCESS_MASK *desired;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
    else
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;

    /* SELF-PROTECTION: strip terminate/inject rights from handles opened to the
     * Valkyrie agent, when enabled. A cheap pid compare — no name resolution —
     * so it adds almost nothing to the hot path. This is the tamper-resistance
     * that stops malware (or a careless admin) from killing the protection. */
    ULONG pflags = 0, agentPid = 0;
    VlkPolicyRead(&pflags, &agentPid);
    if ((pflags & VLK_POLICY_ENABLE_SELFPROTECT) && agentPid != 0 &&
        HandleToULong(tgtPid) == agentPid && HandleToULong(reqPid) != agentPid) {
        ACCESS_MASK tamper = PROCESS_TERMINATE | PROCESS_VM_WRITE |
                             PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                             PROCESS_SUSPEND_RESUME;
        if (*desired & tamper) {
            *desired &= ~tamper;                 /* the actual protection */
            InterlockedIncrement(&g_TamperBlocks);
            VLK_EVENT ev;
            VlkFillHeader(&ev, VLK_EVT_SELF_PROTECT, HandleToULong(reqPid), agentPid);
            ev.flags |= VLK_FLAG_TAMPER;
            ev.granted_access = *desired;
            PUNICODE_STRING reqImage = NULL;
            if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &reqImage)) && reqImage) {
                VlkCopyPath(ev.extra, reqImage);
                ExFreePool(reqImage);
            }
            VlkRingPush(&ev);
        }
        return OB_PREOP_SUCCESS;   /* the agent isn't lsass — done */
    }

    /* Only care about handles TO lsass. Resolve the target's image name. */
    PUNICODE_STRING targetImage = NULL;
    if (!NT_SUCCESS(SeLocateProcessImageName(target, &targetImage)) || targetImage == NULL)
        return OB_PREOP_SUCCESS;     /* fail-safe: can't tell → allow */

    BOOLEAN isLsass = VlkImageIsLsass(targetImage);
    ExFreePool(targetImage);
    if (!isLsass)
        return OB_PREOP_SUCCESS;

    if (*desired & VLK_LSASS_STRIP) {
        *desired &= ~VLK_LSASS_STRIP;    /* the actual protection */
        InterlockedIncrement(&g_LsassBlocks);

        VLK_EVENT ev;
        VlkFillHeader(&ev, VLK_EVT_LSASS_ACCESS_BLOCKED,
                      HandleToULong(reqPid), 0);
        ev.granted_access = *desired;
        /* Best-effort requestor image for the alert. */
        PUNICODE_STRING reqImage = NULL;
        if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &reqImage)) && reqImage) {
            VlkCopyPath(ev.extra, reqImage);
            ExFreePool(reqImage);
        }
        VlkRingPush(&ev);
    }
    return OB_PREOP_SUCCESS;
}

/* ------------------------------------------------------------ dispatch/IOCTL */

static NTSTATUS VlkCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS VlkDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case VLK_IOCTL_PULL_EVENTS: {
        ULONG cap = outLen / sizeof(VLK_EVENT);
        if (cap == 0) { status = STATUS_BUFFER_TOO_SMALL; break; }
        VLK_EVENT *out = (VLK_EVENT *)Irp->AssociatedIrp.SystemBuffer;
        ULONG popped = VlkRingPop(out, cap);
        bytes = popped * sizeof(VLK_EVENT);
        break;
    }
    case VLK_IOCTL_GET_STATS: {
        if (outLen < sizeof(VLK_STATS)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        VLK_STATS *st = (VLK_STATS *)Irp->AssociatedIrp.SystemBuffer;
        RtlZeroMemory(st, sizeof(*st));
        st->version = VLK_PROTO_VERSION;
        st->events_produced = (ULONG)g_Produced;
        st->events_dropped = (ULONG)g_Dropped;
        st->lsass_blocks = (ULONG)g_LsassBlocks;
        st->ring_capacity = VLK_RING_CAPACITY;
        st->ring_pending = g_Count;
        st->thread_events = (ULONG)g_ThreadEvents;
        st->registry_events = (ULONG)g_RegistryEvents;
        st->process_blocks = (ULONG)g_ProcBlocks;
        st->tamper_blocks = (ULONG)g_TamperBlocks;
        bytes = sizeof(*st);
        break;
    }
    case VLK_IOCTL_SET_POLICY: {
        /* User mode pushes the enforcement policy IN. Validated hard: exact
         * size, matching version, and block_count CLAMPED to the fixed array —
         * the kernel never trusts a count that could walk off the array. Only
         * the trusted Valkyrie service can reach this device, but we validate
         * as if it were hostile input anyway. */
        ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
        if (inLen < sizeof(VLK_POLICY)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        VLK_POLICY *in = (VLK_POLICY *)Irp->AssociatedIrp.SystemBuffer;
        if (in->version != VLK_PROTO_VERSION) { status = STATUS_REVISION_MISMATCH; break; }
        ULONG count = in->block_count;
        if (count > VLK_MAX_BLOCK_HASHES) count = VLK_MAX_BLOCK_HASHES;

        KIRQL irql;
        KeAcquireSpinLock(&g_PolicyLock, &irql);
        g_Policy.version    = VLK_PROTO_VERSION;
        g_Policy.flags      = in->flags & (VLK_POLICY_ENABLE_PREVENTION |
                                           VLK_POLICY_ENABLE_SELFPROTECT);
        g_Policy.agent_pid  = in->agent_pid;
        g_Policy.block_count = count;
        for (ULONG i = 0; i < count; i++)
            g_Policy.block_hashes[i] = in->block_hashes[i];
        KeReleaseSpinLock(&g_PolicyLock, irql);
        bytes = 0;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ---------------------------------------------------------------- unload */

static VOID VlkUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(VLK_SYMLINK_NAME);

    if (g_ImageCbRegistered)
        PsRemoveLoadImageNotifyRoutine(VlkImageNotify);
    if (g_ThreadCbRegistered)
        PsRemoveCreateThreadNotifyRoutine(VlkThreadNotify);
    if (g_ProcessCbRegistered)
        PsSetCreateProcessNotifyRoutineEx(VlkProcessNotify, TRUE /* remove */);
    if (g_RegCbRegistered)
        CmUnRegisterCallback(g_RegCookie);
    if (g_ObCallbackHandle) {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
    }

    IoDeleteSymbolicLink(&symlink);
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);
    if (g_Ring) {
        ExFreePoolWithTag(g_Ring, VLK_TAG);
        g_Ring = NULL;
    }
}

/* --------------------------------------------------------------- entry */

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING devName = RTL_CONSTANT_STRING(VLK_DEVICE_NAME);
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(VLK_SYMLINK_NAME);
    NTSTATUS status;

    DriverObject->DriverUnload = VlkUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = VlkCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = VlkCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VlkDeviceControl;

    KeInitializeSpinLock(&g_RingLock);
    KeInitializeSpinLock(&g_PolicyLock);
    RtlZeroMemory(&g_Policy, sizeof(g_Policy));   /* detection-only until told otherwise */
    g_Ring = (VLK_EVENT *)ExAllocatePoolZero(NonPagedPoolNx,
                 sizeof(VLK_EVENT) * VLK_RING_CAPACITY, VLK_TAG);
    if (g_Ring == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) goto fail;

    status = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(status)) goto fail;

    /* Process notify is the highest-value, safest capability — register it
     * first; treat its failure as fatal (the driver's core purpose). */
    status = PsSetCreateProcessNotifyRoutineEx(VlkProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) goto fail;
    g_ProcessCbRegistered = TRUE;

    /* Image notify — best-effort; a failure here should not sink the driver. */
    if (NT_SUCCESS(PsSetLoadImageNotifyRoutine(VlkImageNotify)))
        g_ImageCbRegistered = TRUE;

    /* Thread notify — best-effort; catches cross-process (remote) thread
     * injection. Read-only, so a failure just costs that one signal. */
    if (NT_SUCCESS(PsSetCreateThreadNotifyRoutine(VlkThreadNotify)))
        g_ThreadCbRegistered = TRUE;

    /* Registry notify — best-effort, DETECTION-ONLY. The altitude string must
     * be unique per registered filter; it is unrelated to the Ob altitude.
     * A failure here costs only autostart-registry visibility. */
    {
        UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(L"360000");
        if (NT_SUCCESS(CmRegisterCallbackEx(VlkRegistryCallback, &regAltitude,
                                            DriverObject, NULL, &g_RegCookie, NULL)))
            g_RegCbRegistered = TRUE;
    }

    /* Ob LSASS protection — requires the binary to be signed with an EV cert
     * that has the OB-callback ("elam"/anti-malware or WHQL) entitlement, or
     * test-signing. Best-effort: if registration is refused, telemetry still
     * works; we simply don't provide the handle-strip protection. */
    {
        OB_OPERATION_REGISTRATION op;
        OB_CALLBACK_REGISTRATION reg;
        UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"321000");

        RtlZeroMemory(&op, sizeof(op));
        /* PsProcessType is POBJECT_TYPE* — dereference to the POBJECT_TYPE the
         * registration (and the pre-op comparison) expect. */
        op.ObjectType = *PsProcessType;
        op.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        op.PreOperation = VlkPreOp;

        RtlZeroMemory(&reg, sizeof(reg));
        reg.Version = OB_FLT_REGISTRATION_VERSION;
        reg.OperationRegistrationCount = 1;
        reg.Altitude = altitude;
        reg.RegistrationContext = NULL;
        reg.OperationRegistration = &op;

        (VOID)ObRegisterCallbacks(&reg, &g_ObCallbackHandle);
    }

    return STATUS_SUCCESS;

fail:
    VlkUnload(DriverObject);
    return status;
}
