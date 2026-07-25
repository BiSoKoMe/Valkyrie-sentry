/*
 * valkyrie_shared.h — the ONE wire contract shared by the kernel driver and
 * the user-mode bridge (valkyrie/kernel_bridge.py). Both sides MUST agree on
 * these layouts byte-for-byte; the Python side mirrors them with `struct`.
 *
 * Design choices that keep the kernel side safe and simple:
 *   - FIXED-SIZE records. No variable-length parsing in kernel; the ring
 *     buffer is a plain array and the user copy-out is a single memcpy.
 *   - Little-endian, packed. Windows x64 is LE; packing removes ambiguity.
 *   - Paths are fixed WCHAR[260] (MAX_PATH), always null-terminated, truncated
 *     if longer. The bridge treats them as UTF-16-LE.
 */

#ifndef VALKYRIE_SHARED_H
#define VALKYRIE_SHARED_H

/* Bump when the record layout changes so a stale bridge refuses to parse. */
#define VLK_PROTO_VERSION   1

#define VLK_PATH_LEN        260     /* WCHARs, incl. null terminator */

/* Event kinds the driver emits. */
#define VLK_EVT_PROCESS_CREATE          1
#define VLK_EVT_PROCESS_EXIT            2
#define VLK_EVT_IMAGE_LOAD              3
#define VLK_EVT_LSASS_ACCESS_BLOCKED    4   /* Ob-callback stripped rights */

/* Per-record flags (bitmask). */
#define VLK_FLAG_NONE               0x00000000
#define VLK_FLAG_SYSTEM_PROC        0x00000001  /* actor is a system process */
#define VLK_FLAG_REMOTE_IMAGE       0x00000002  /* image loaded from a UNC/remote path */

#pragma pack(push, 1)
typedef struct _VLK_EVENT {
    unsigned int   version;             /* == VLK_PROTO_VERSION            */
    unsigned int   event_type;          /* VLK_EVT_*                       */
    unsigned long long timestamp;       /* 100ns ticks since 1601 (UTC)    */
    unsigned int   pid;                 /* actor process id                */
    unsigned int   ppid;                /* parent/creator pid (authoritative) */
    unsigned int   flags;               /* VLK_FLAG_*                      */
    unsigned int   granted_access;      /* LSASS event: rights left after strip */
    unsigned short image[VLK_PATH_LEN]; /* actor image path (WCHAR, null-term) */
    unsigned short extra[VLK_PATH_LEN]; /* parent image | module path | requestor image */
} VLK_EVENT;
#pragma pack(pop)

/* Device + symbolic link the bridge opens (\\.\Valkyrie). */
#define VLK_DEVICE_NAME     L"\\Device\\ValkyrieKm"
#define VLK_SYMLINK_NAME    L"\\DosDevices\\ValkyrieKm"
#define VLK_USERMODE_PATH   "\\\\.\\ValkyrieKm"

/*
 * IOCTLs. FILE_DEVICE_UNKNOWN, buffered I/O, read access — the bridge only
 * ever reads telemetry out; it never writes into the kernel.
 */
#define VLK_IOCTL_PULL_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define VLK_IOCTL_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

/* Stats block returned by VLK_IOCTL_GET_STATS. */
#pragma pack(push, 1)
typedef struct _VLK_STATS {
    unsigned int version;
    unsigned int events_produced;   /* total pushed into the ring          */
    unsigned int events_dropped;    /* ring-full drops (backpressure)      */
    unsigned int lsass_blocks;      /* handle-strips performed             */
    unsigned int ring_capacity;
    unsigned int ring_pending;      /* not yet pulled                      */
} VLK_STATS;
#pragma pack(pop)

#endif /* VALKYRIE_SHARED_H */
