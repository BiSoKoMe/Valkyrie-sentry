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
 *   - The POLICY the driver enforces (which images to deny, which pid to
 *     protect) is a fixed-size struct pushed IN from user mode — the kernel
 *     never parses a list, only compares against a bounded hash array.
 */

#ifndef VALKYRIE_SHARED_H
#define VALKYRIE_SHARED_H

/* Bump when the record OR policy layout changes so a stale bridge refuses to
 * parse / a stale driver refuses a mismatched policy. v2 adds thread-injection
 * and registry telemetry, plus process-block prevention and self-protection. */
#define VLK_PROTO_VERSION   2

#define VLK_PATH_LEN        260     /* WCHARs, incl. null terminator */

/* Event kinds the driver emits. */
#define VLK_EVT_PROCESS_CREATE          1
#define VLK_EVT_PROCESS_EXIT            2
#define VLK_EVT_IMAGE_LOAD              3
#define VLK_EVT_LSASS_ACCESS_BLOCKED    4   /* Ob-callback stripped rights */
#define VLK_EVT_THREAD_CREATE           5   /* cross-process thread (injection) */
#define VLK_EVT_REGISTRY_SET            6   /* write to an autostart key */
#define VLK_EVT_PROCESS_BLOCKED         7   /* creation DENIED by policy (prevention) */
#define VLK_EVT_SELF_PROTECT            8   /* tamper handle to the agent stripped */

/* Per-record flags (bitmask). */
#define VLK_FLAG_NONE               0x00000000
#define VLK_FLAG_SYSTEM_PROC        0x00000001  /* actor is a system process */
#define VLK_FLAG_REMOTE_IMAGE       0x00000002  /* image loaded from a UNC/remote path */
#define VLK_FLAG_REMOTE_THREAD      0x00000004  /* thread created cross-process (injection) */
#define VLK_FLAG_BLOCKED            0x00000008  /* the driver prevented this operation */
#define VLK_FLAG_TAMPER             0x00000010  /* attempt to tamper with the agent */
#define VLK_FLAG_AUTOSTART          0x00000020  /* registry write to an autostart key */

#pragma pack(push, 1)
typedef struct _VLK_EVENT {
    unsigned int   version;             /* == VLK_PROTO_VERSION            */
    unsigned int   event_type;          /* VLK_EVT_*                       */
    unsigned long long timestamp;       /* 100ns ticks since 1601 (UTC)    */
    unsigned int   pid;                 /* actor process id                */
    unsigned int   ppid;                /* parent/creator pid (authoritative) */
    unsigned int   flags;               /* VLK_FLAG_*                      */
    unsigned int   granted_access;      /* LSASS/self-protect: rights left after strip */
    unsigned short image[VLK_PATH_LEN]; /* actor image path (WCHAR, null-term) */
    unsigned short extra[VLK_PATH_LEN]; /* parent image | module | requestor | key path */
} VLK_EVENT;
#pragma pack(pop)

/* Device + symbolic link the bridge opens (\\.\Valkyrie). */
#define VLK_DEVICE_NAME     L"\\Device\\ValkyrieKm"
#define VLK_SYMLINK_NAME    L"\\DosDevices\\ValkyrieKm"
#define VLK_USERMODE_PATH   "\\\\.\\ValkyrieKm"

/*
 * IOCTLs. FILE_DEVICE_UNKNOWN, buffered I/O. PULL/STATS are read-only; SET_POLICY
 * is the one path user mode writes IN — a fixed-size, validated struct, never a
 * variable-length list.
 */
#define VLK_IOCTL_PULL_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define VLK_IOCTL_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define VLK_IOCTL_SET_POLICY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)

/*
 * Enforcement policy — pushed from user mode. The driver defaults to
 * DETECTION-ONLY (both enable bits clear, agent_pid 0): it never blocks a
 * process or protects a pid until the trusted user-mode service explicitly
 * turns it on. This is the safety default — a driver that ships blocking-on
 * is how you brick a fleet.
 */
#define VLK_POLICY_ENABLE_PREVENTION    0x00000001  /* allow deny-on-create */
#define VLK_POLICY_ENABLE_SELFPROTECT   0x00000002  /* allow agent handle-strip */

#define VLK_MAX_BLOCK_HASHES  256    /* bounded; kernel never grows this */

#pragma pack(push, 1)
typedef struct _VLK_POLICY {
    unsigned int version;                         /* == VLK_PROTO_VERSION */
    unsigned int flags;                           /* VLK_POLICY_*         */
    unsigned int agent_pid;                        /* pid to self-protect (0 = none) */
    unsigned int block_count;                      /* valid entries in block_hashes */
    unsigned int block_hashes[VLK_MAX_BLOCK_HASHES]; /* FNV-1a of lowercased image basename to DENY */
} VLK_POLICY;
#pragma pack(pop)

/* Stats block returned by VLK_IOCTL_GET_STATS. */
#pragma pack(push, 1)
typedef struct _VLK_STATS {
    unsigned int version;
    unsigned int events_produced;   /* total pushed into the ring          */
    unsigned int events_dropped;    /* ring-full drops (backpressure)      */
    unsigned int lsass_blocks;      /* handle-strips performed             */
    unsigned int ring_capacity;
    unsigned int ring_pending;      /* not yet pulled                      */
    unsigned int thread_events;     /* cross-process thread creations seen */
    unsigned int registry_events;   /* autostart registry writes seen      */
    unsigned int process_blocks;    /* creations denied by prevention      */
    unsigned int tamper_blocks;     /* self-protection handle-strips        */
} VLK_STATS;
#pragma pack(pop)

#endif /* VALKYRIE_SHARED_H */
