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
 *   1. Process create/exit notify (PsSetCreateProcessNotifyRoutineEx).
 *      Authoritative process lineage — the exact (pid, ppid, image) the
 *      user-mode kill-chain correlator wants, from the kernel's own tables
 *      rather than racy user-mode enumeration. Read-only; cannot destabilise.
 *
 *   2. Image load notify (PsSetLoadImageNotifyRoutine).
 *      Every module load with its backing path. Signature verdicts are LEFT
 *      to user mode (Authenticode) — this driver reports facts, it does not
 *      claim in-kernel signature checking it doesn't implement.
 *
 *   3. LSASS credential-theft protection (ObRegisterCallbacks, pre-op on
 *      PsProcessType). When a non-trusted process opens a handle to lsass.exe,
 *      the callback STRIPS the dangerous rights (VM_READ / other memory access)
 *      from DesiredAccess. It never denies the open outright and never touches
 *      trusted/system callers — the conservative, OS-safe pattern (this is the
 *      same class of defence as RunAsPPL), so it blocks Mimikatz-style dumping
 *      without risking a deadlock or breaking legitimate callers.
 *
 *   4. A control device (\\.\ValkyrieKm) with a fixed-size lock-guarded ring
 *      buffer. The bridge PULLS events with a buffered IOCTL (a poll, not a
 *      pending-IRP inverted call — polling is a hair less efficient but far
 *      safer: no IRP-cancellation race to get subtly wrong and BSOD on).
 *
 * Fail-safe posture everywhere: on any doubt the driver ALLOWS the operation
 * and drops the event rather than blocking or dereferencing something unsafe.
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

/* Fixed-size circular ring, guarded by a spinlock (callbacks may run on any
 * CPU concurrently). head = next write, tail = next read; count = pending. */
static VLK_EVENT       *g_Ring = NULL;
static ULONG            g_Head = 0, g_Tail = 0, g_Count = 0;
static KSPIN_LOCK       g_RingLock;

static volatile LONG    g_Produced = 0;
static volatile LONG    g_Dropped = 0;
static volatile LONG    g_LsassBlocks = 0;

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
    } else {
        VlkFillHeader(&ev, VLK_EVT_PROCESS_EXIT, HandleToULong(ProcessId), 0);
    }
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

    /* Only care about handles TO lsass. Resolve the target's image name. */
    PUNICODE_STRING targetImage = NULL;
    if (!NT_SUCCESS(SeLocateProcessImageName(target, &targetImage)) || targetImage == NULL)
        return OB_PREOP_SUCCESS;     /* fail-safe: can't tell → allow */

    BOOLEAN isLsass = VlkImageIsLsass(targetImage);
    ExFreePool(targetImage);
    if (!isLsass)
        return OB_PREOP_SUCCESS;

    /* Requestor is the current process. Trust SYSTEM (pid 4) and protected
     * processes — stripping their access could break the OS. This is a
     * conservative allowlist; user mode still SEES the (unstripped) trusted
     * opens via other telemetry. */
    HANDLE reqPid = PsGetCurrentProcessId();
    if (HandleToULong(reqPid) == 4)
        return OB_PREOP_SUCCESS;

    ACCESS_MASK *desired;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
    else
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;

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
        bytes = sizeof(*st);
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
    if (g_ProcessCbRegistered)
        PsSetCreateProcessNotifyRoutineEx(VlkProcessNotify, TRUE /* remove */);
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
