# ADR 0031 - Kernel prevention + self-protection (the detect->prevent leap)

Date: 2026-07-25 . Status: accepted . Follows: ADR 0026

## Context

ADR 0026 shipped the Valkyrie kernel driver as real, reviewable, unbuilt WDK
source: authoritative process lineage, image-load visibility, and LSASS
credential-theft protection, all as **telemetry** plus one narrow protection.
The honest gap between that and a Falcon-class kernel component was two things a
real EDR driver does that ours did not:

1. **Prevention.** Seeing a malicious launch is not stopping it. A real driver
   can *deny* process creation from the kernel.
2. **Tamper resistance.** An EDR that a local admin (or admin-level malware) can
   `TerminateProcess` is theatre. CrowdStrike's kernel component is, famously,
   very hard to kill.

Adding kernel capability is also where the danger lives: CrowdStrike's own July
2024 outage - a bad kernel-driver content update that bugchecked ~8.5M machines
- is the standing reminder that a driver's **first** duty is to not brick the
host. So the design bar here is capability *and* a safety story strong enough
that the capability can't be turned into a self-inflicted outage.

## Decision

Extend the driver (protocol v2) with four capabilities and a pushed policy,
each gated by an explicit safety design.

- **Process-launch prevention.** In the existing create-notify callback, when a
  policy has enabled prevention and the new image's basename hash is on the
  block list, set `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED` - the
  kernel aborts the launch. Guarded three ways: prevention is **off by
  default**; an image under `\Windows\` is **never** blocked (a bad/hostile list
  cannot stop the OS); and the block list is a **fixed, bounded, validated**
  hash array, never a variable list parsed in kernel.
- **Agent self-protection.** In the Ob pre-op callback, strip
  `PROCESS_TERMINATE`/VM-write/inject rights from non-SYSTEM handles opened to
  the agent pid - same proven strip-not-deny pattern as the LSASS path. Off by
  default; SYSTEM exempt.
- **Remote-thread injection** detection (`PsSetCreateThreadNotifyRoutine`):
  cross-process thread creation = `CreateRemoteThread` (T1055). Read-only.
- **Autostart-registry** detection (`CmRegisterCallbackEx`): writes to
  Run/RunOnce/Services keys (T1547/T1543). **Detection-only** - always returns
  `STATUS_SUCCESS`, never alters a registry op, because a registry callback that
  gets blocking wrong hangs the machine.
- **Policy intake** (`VLK_IOCTL_SET_POLICY`): user mode pushes a fixed-size
  `VLK_POLICY` (version-checked, count-clamped) carrying the enable bits, the
  agent pid, and the block-list hashes. The hash is FNV-1a over the lowercased
  image basename, computed identically in `VlkHashImageBasename` (kernel) and
  `kernel_bridge.fnv1a_32` (Python), so a block list authored in user mode
  matches in the kernel byte-for-byte.

The user-mode bridge parses the four new event kinds into the same
`TelemetryEvent` stream (thread-inject -> T1055; registry -> T1547.001; a blocked
launch -> an `action=blocked`, `prevented` incident; a tamper attempt ->
T1562.001), and gains `build_policy()` + `push_policy()`.

## Consequences

- The driver source now matches the *shape* of a real EDR kernel component:
  telemetry, injection + persistence sensors, credential-theft protection,
  process-block **prevention**, and **self-protection** - with the safety rails
  that make prevention deployable rather than dangerous.
- The fully-testable half is tested: `tests/test_kernel_bridge.py` (40+ checks)
  covers every new event's normalisation, FNV hash parity against a hand-
  computed reference, and policy serialisation safety (detection-only default,
  dedup, cap/overflow clamp).

## Honest boundaries (unchanged and reinforced)

- **Still unbuilt, unsigned, unloaded, untested as a binary.** Every capability
  above is reviewable source. None of it runs until a developer builds, signs,
  loads, and validates it in a VM per `driver/README.md`. Nothing in the product
  claims "kernel prevention active" unless the bridge reports the device open.
- **Prevention/self-protection are OFF until explicitly enabled** by a pushed
  policy - chosen precisely so an unvalidated driver cannot brick a machine.
- **The July-2024 lesson applies to us too.** These are the exact class of
  kernel changes that, shipped carelessly, cause outages. The safety rails
  (default-off, `\Windows\` exemption, bounded validated policy, detection-only
  registry, fail-open everywhere) are load-bearing, not decoration - and the VM
  validation checklist (README steps 3-6) is mandatory before trust.
- **Self-protection is not un-killable.** It raises the bar (strips common
  tamper rights from user-mode handles); it does not defeat a kernel-level
  attacker, a boot-time removal, or Safe Mode. No userland-or-single-driver
  design can, and claiming otherwise would be dishonest.
